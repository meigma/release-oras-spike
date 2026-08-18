package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/errcode"
	"oras.land/oras-go/v2/registry/remote/retry"
)

// stateClass classifies a registry read or write outcome so an engine can
// decide between accept, retry, fail-closed, and reconcile. This is the taxonomy
// PR 3/PR 4 will encode; the spike exists to confirm the wire behavior behind
// each class.
type stateClass string

const (
	// classAbsent means the reference does not exist.
	classAbsent stateClass = "absent"
	// classPresent means the reference exists and resolved.
	classPresent stateClass = "present"
	// classAuth means the registry rejected the credential or scope.
	classAuth stateClass = "auth"
	// classRetryable means a transient transport or server condition.
	classRetryable stateClass = "retryable"
	// classMalformed means the remote returned content that violates the contract.
	classMalformed stateClass = "malformed"
	// classUnknown means the outcome could not be classified and must be
	// reconciled by re-reading fresh state.
	classUnknown stateClass = "unknown"
)

// classify maps an oras-go error to a state class.
func classify(err error) stateClass {
	if err == nil {
		return classPresent
	}
	if errors.Is(err, errdef.ErrNotFound) {
		return classAbsent
	}

	var resp *errcode.ErrorResponse
	if errors.As(err, &resp) {
		switch {
		case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
			return classAuth
		case resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
			return classRetryable
		case resp.StatusCode == http.StatusNotFound:
			return classAbsent
		default:
			return classMalformed
		}
	}

	return classUnknown
}

// openRepository connects to a repository, using plain HTTP for a local test
// registry and token auth for a real one. Credentials stay in memory: nothing is
// written to a docker config, which is what obsoletes the workflow's
// login/logout steps (inventory OP-09/OP-20).
func openRepository(ref string, plainHTTP bool) (*remote.Repository, error) {
	repo, err := remote.NewRepository(ref)
	if err != nil {
		return nil, fmt.Errorf("parse reference %q: %w", ref, err)
	}
	repo.PlainHTTP = plainHTTP

	username, password := os.Getenv("REGISTRY_USERNAME"), os.Getenv("REGISTRY_PASSWORD")
	if password != "" {
		repo.Client = &auth.Client{
			Client: retry.DefaultClient,
			Cache:  auth.NewCache(),
			Credential: auth.StaticCredential(repo.Reference.Registry, auth.Credential{
				Username: username,
				Password: password,
			}),
		}
	}

	return repo, nil
}

// resolveState resolves a reference and returns its descriptor plus a class.
func resolveState(ctx context.Context, repo *remote.Repository, reference string) (v1.Descriptor, stateClass, error) {
	desc, err := repo.Resolve(ctx, reference)
	class := classify(err)
	if class == classAbsent {
		return v1.Descriptor{}, class, nil
	}
	if err != nil {
		return v1.Descriptor{}, class, err
	}
	return desc, classPresent, nil
}

// pushGraph copies the whole layout graph to the registry addressed only by
// digest, mirroring inventory OP-13/OP-14: no tag is created here, so nothing is
// consumer-visible until tags are committed after trust metadata exists
// (invariant 14). failAfter > 0 aborts after that many pushed blobs to simulate
// a partial publication.
func pushGraph(ctx context.Context, layoutDir string, root v1.Descriptor, repo *remote.Repository, failAfter int) (int, error) {
	store, err := oci.New(layoutDir)
	if err != nil {
		return 0, fmt.Errorf("open layout: %w", err)
	}

	counter := &countingTarget{inner: repo, failAfter: failAfter}

	opts := oras.DefaultCopyGraphOptions
	if err := oras.CopyGraph(ctx, store, counter, root, opts); err != nil {
		return counter.count(), fmt.Errorf("copy graph: %w", err)
	}

	return counter.count(), nil
}

// verifyDigestResolution requires the pushed index to resolve by digest to the
// exact expected digest (inventory OP-14's equality requirement).
func verifyDigestResolution(ctx context.Context, repo *remote.Repository, expected v1.Descriptor) error {
	desc, class, err := resolveState(ctx, repo, expected.Digest.String())
	if err != nil {
		return fmt.Errorf("resolve pushed index (%s): %w", class, err)
	}
	if class != classPresent {
		return fmt.Errorf("pushed index resolved as %s", class)
	}
	if desc.Digest != expected.Digest {
		return fmt.Errorf("resolved digest %s, expected %s", desc.Digest, expected.Digest)
	}
	return nil
}

// commitTags applies tags one at a time and verifies each resulting tag resolves
// to the expected digest, mirroring inventory OP-19's serial, verified commit.
func commitTags(ctx context.Context, repo *remote.Repository, desc v1.Descriptor, tags []string) error {
	for _, tag := range tags {
		if err := repo.Tag(ctx, desc, tag); err != nil {
			return fmt.Errorf("tag %q (%s): %w", tag, classify(err), err)
		}

		observed, class, err := resolveState(ctx, repo, tag)
		if err != nil {
			return fmt.Errorf("verify tag %q (%s): %w", tag, class, err)
		}
		if class != classPresent || observed.Digest != desc.Digest {
			return fmt.Errorf("tag %q resolved to %s (%s), expected %s", tag, observed.Digest, class, desc.Digest)
		}
	}
	return nil
}

// countingTarget wraps a push target so the spike can abort mid-publication.
// oras.CopyGraph pushes concurrently (DefaultCopyGraphOptions sets Concurrency
// to 3), so this counter must be mutex-guarded and the observed abort point is
// not strictly ordered.
type countingTarget struct {
	// mu guards pushed.
	mu sync.Mutex
	// inner is the real target.
	inner *remote.Repository
	// failAfter aborts the copy after this many successful pushes when positive.
	failAfter int
	// pushed counts successful pushes.
	pushed int
}

// errInjectedFailpoint marks a deliberate mid-publication abort.
var errInjectedFailpoint = errors.New("injected failpoint")

// Push implements content.Storage.
func (c *countingTarget) Push(ctx context.Context, expected v1.Descriptor, content io.Reader) error {
	c.mu.Lock()
	stop := c.failAfter > 0 && c.pushed >= c.failAfter
	c.mu.Unlock()
	if stop {
		return errInjectedFailpoint
	}

	if err := c.inner.Push(ctx, expected, content); err != nil {
		return err
	}

	c.mu.Lock()
	c.pushed++
	c.mu.Unlock()

	return nil
}

// count reports the number of successful pushes.
func (c *countingTarget) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pushed
}

// Exists implements content.Storage.
func (c *countingTarget) Exists(ctx context.Context, target v1.Descriptor) (bool, error) {
	return c.inner.Exists(ctx, target)
}

// Fetch implements content.Storage.
func (c *countingTarget) Fetch(ctx context.Context, target v1.Descriptor) (io.ReadCloser, error) {
	return c.inner.Fetch(ctx, target)
}
