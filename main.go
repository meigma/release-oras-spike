// Command oras-spike probes oras-go v2 against a registry to prove the release
// publisher's required semantics before the real adapter is written
// (architecture spike B). It is throwaway evidence code, not the adapter.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	gcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote"
)

// report is the machine-readable spike result.
type report struct {
	// Mode is "local" or "remote".
	Mode string `json:"mode"`
	// Reference is the repository the probe published to.
	Reference string `json:"reference"`
	// Version is the synthetic release version used.
	Version string `json:"version"`
	// IndexDigest is the digest of the exact index bytes.
	IndexDigest string `json:"index_digest"`
	// PlatformDigests maps architecture to platform manifest digest.
	PlatformDigests map[string]string `json:"platform_digests"`
	// SBOMPaths maps apk architecture to SBOM file path.
	SBOMPaths map[string]string `json:"sbom_paths"`
	// Steps records each probe step's outcome.
	Steps []step `json:"steps"`
}

// step is one probe observation.
type step struct {
	// Name identifies the probe.
	Name string `json:"name"`
	// Class is the observed state class, when the step classifies one.
	Class string `json:"class,omitempty"`
	// Detail carries human-readable evidence.
	Detail string `json:"detail,omitempty"`
	// OK reports whether the step met its expectation.
	OK bool `json:"ok"`
}

// main runs the probe and prints one JSON report to stdout.
func main() {
	mode := flag.String("mode", "local", "local (in-process registry) or remote")
	ref := flag.String("ref", "", "remote repository reference, e.g. ghcr.io/owner/name")
	version := flag.String("version", "9.9.9", "synthetic release version")
	plainHTTP := flag.Bool("plain-http", false, "use plain HTTP for the remote reference")
	failpoints := flag.Bool("failpoints", true, "run partial-publication recovery probes")
	stopBeforeTags := flag.Bool("stop-before-tags", false, "publish and verify by digest only; apply no tags")
	tagsOnly := flag.Bool("tags-only", false, "skip publication; apply and verify tags for an already-published index")
	flag.Parse()

	phase := phaseAll
	switch {
	case *stopBeforeTags && *tagsOnly:
		fmt.Fprintln(os.Stderr, "spike failed: -stop-before-tags and -tags-only are mutually exclusive")
		os.Exit(2)
	case *stopBeforeTags:
		phase = phasePublish
	case *tagsOnly:
		phase = phaseTags
	}

	if err := run(*mode, *ref, *version, *plainHTTP, *failpoints, phase); err != nil {
		fmt.Fprintf(os.Stderr, "spike failed: %v\n", err)
		os.Exit(1)
	}
}

// run executes the probe sequence and writes the report.
// phase selects which half of the two-phase publication the probe performs,
// mirroring the architecture's prepare/finalize split: content and signatures
// first, public tags only after trust metadata exists (invariant 14).
type phase int

const (
	// phaseAll runs publication and tagging in one process.
	phaseAll phase = iota
	// phasePublish pushes and verifies by digest, applying no tags.
	phasePublish
	// phaseTags applies and verifies tags for already-published content.
	phaseTags
)

func run(mode, ref, version string, plainHTTP, failpoints bool, ph phase) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if mode == "local" {
		server := httptest.NewServer(gcrregistry.New(gcrregistry.Logger(log.New(io.Discard, "", 0))))
		defer server.Close()
		ref = server.Listener.Addr().String() + "/spike/release-cli"
		plainHTTP = true
	}
	if ref == "" {
		return errors.New("-ref is required in remote mode")
	}

	root, err := os.MkdirTemp("", "oras-spike-*")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}

	built, err := buildLayout(ctx, root, version)
	if err != nil {
		return err
	}

	rep := &report{
		Mode:            mode,
		Reference:       ref,
		Version:         version,
		IndexDigest:     built.Index.Digest.String(),
		PlatformDigests: map[string]string{},
		SBOMPaths:       built.SBOMPaths,
	}
	for arch, desc := range built.Manifests {
		rep.PlatformDigests[arch] = desc.Digest.String()
	}

	probeErr := probe(ctx, rep, built, ref, plainHTTP, failpoints, ph)
	emit(rep)
	if probeErr != nil {
		return probeErr
	}

	for _, s := range rep.Steps {
		if !s.OK {
			return fmt.Errorf("probe step %q did not meet expectation", s.Name)
		}
	}
	return nil
}

// probe runs every registry observation the publisher depends on.
func probe(
	ctx context.Context,
	rep *report,
	built *builtLayout,
	ref string,
	plainHTTP, failpoints bool,
	ph phase,
) error {
	repo, err := openRepository(ref, plainHTTP)
	if err != nil {
		return err
	}

	exactTag := "v" + built.Version

	if ph == phaseTags {
		return probeTags(ctx, rep, built, repo, exactTag)
	}

	// 1. Exact tag must be absent before publication (invariant 11 precondition).
	_, class, err := resolveState(ctx, repo, exactTag)
	if err != nil {
		return fmt.Errorf("pre-publication resolve: %w", err)
	}
	rep.Steps = append(rep.Steps, step{
		Name:   "exact-tag-absent-before-push",
		Class:  string(class),
		OK:     class == classAbsent,
		Detail: exactTag,
	})

	// 2. Partial publication then recovery: abort mid-graph, then re-push.
	if failpoints {
		pushed, pushErr := pushGraph(ctx, built.Dir, built.Index, repo, 2)
		rep.Steps = append(rep.Steps, step{
			Name:   "partial-push-aborts",
			OK:     errors.Is(pushErr, errInjectedFailpoint),
			Detail: fmt.Sprintf("pushed=%d err=%v", pushed, pushErr),
		})

		_, class, err := resolveState(ctx, repo, exactTag)
		if err != nil {
			return fmt.Errorf("resolve after partial push: %w", err)
		}
		rep.Steps = append(rep.Steps, step{
			Name:   "partial-push-leaves-no-tag",
			Class:  string(class),
			OK:     class == classAbsent,
			Detail: "digest-only content is not consumer-visible",
		})
	}

	// 3. Full digest publication converges over already-present content.
	pushed, err := pushGraph(ctx, built.Dir, built.Index, repo, 0)
	if err != nil {
		return fmt.Errorf("full push: %w", err)
	}
	rep.Steps = append(rep.Steps, step{
		Name:   "digest-push-completes",
		OK:     true,
		Detail: fmt.Sprintf("pushed=%d after partial attempt", pushed),
	})

	// 4. Index resolves by digest to exactly the expected digest (OP-14).
	if err := verifyDigestResolution(ctx, repo, built.Index); err != nil {
		rep.Steps = append(rep.Steps, step{Name: "index-resolves-by-digest", OK: false, Detail: err.Error()})
		return err
	}
	rep.Steps = append(rep.Steps, step{
		Name:   "index-resolves-by-digest",
		OK:     true,
		Detail: built.Index.Digest.String(),
	})

	// 5. Both platform manifests resolve by digest (OP-07/OP-14).
	for arch, desc := range built.Manifests {
		observed, class, err := resolveState(ctx, repo, desc.Digest.String())
		ok := err == nil && class == classPresent && observed.Digest == desc.Digest
		rep.Steps = append(rep.Steps, step{
			Name:   "platform-manifest-resolves-" + arch,
			Class:  string(class),
			OK:     ok,
			Detail: desc.Digest.String(),
		})
		if !ok {
			return fmt.Errorf("platform manifest %s did not resolve: %v", arch, err)
		}
	}

	// 6. Version annotation is readable from the pushed index (OP-12 input).
	annotation, err := fetchVersionAnnotation(ctx, repo, built.Index)
	rep.Steps = append(rep.Steps, step{
		Name:   "index-version-annotation-readable",
		OK:     err == nil && annotation == built.Version,
		Detail: fmt.Sprintf("annotation=%q err=%v", annotation, err),
	})
	if err != nil {
		return err
	}

	if ph == phasePublish {
		_, class, err := resolveState(ctx, repo, exactTag)
		if err != nil {
			return fmt.Errorf("post-publication resolve: %w", err)
		}
		rep.Steps = append(rep.Steps, step{
			Name:   "digest-published-without-public-tag",
			Class:  string(class),
			OK:     class == classAbsent,
			Detail: "signatures and attestations can now precede any tag",
		})
		return nil
	}

	// 7. Serial verified tag commit (OP-19).
	tags := []string{exactTag, majorMinor(built.Version), major(built.Version), "latest"}
	if err := commitTags(ctx, repo, built.Index, tags); err != nil {
		rep.Steps = append(rep.Steps, step{Name: "serial-verified-tag-commit", OK: false, Detail: err.Error()})
		return err
	}
	rep.Steps = append(rep.Steps, step{
		Name:   "serial-verified-tag-commit",
		OK:     true,
		Detail: fmt.Sprintf("%v", tags),
	})

	// 8. Re-tagging the same digest is accepted (rerun reconciliation, invariant 11).
	if err := commitTags(ctx, repo, built.Index, []string{exactTag}); err != nil {
		rep.Steps = append(rep.Steps, step{Name: "retag-same-digest-accepted", OK: false, Detail: err.Error()})
		return err
	}
	rep.Steps = append(rep.Steps, step{Name: "retag-same-digest-accepted", OK: true})

	// 9. The exact tag still points at the published digest: no drift.
	drift, err := detectExactTagDrift(ctx, repo, exactTag, built.Index)
	rep.Steps = append(rep.Steps, step{
		Name:   "exact-tag-drift-detectable",
		OK:     err == nil && !drift,
		Detail: fmt.Sprintf("drift=%v err=%v", drift, err),
	})

	// 10. Absent reference classification for a nonexistent tag.
	_, class, err = resolveState(ctx, repo, "does-not-exist")
	rep.Steps = append(rep.Steps, step{
		Name:   "absent-tag-classified",
		Class:  string(class),
		OK:     err == nil && class == classAbsent,
		Detail: "not-found is distinguishable from failure",
	})

	return nil
}

// probeTags is the finalize half: it refuses to tag unless the already-published
// index still resolves by digest, then applies and verifies tags serially.
func probeTags(
	ctx context.Context,
	rep *report,
	built *builtLayout,
	repo *remote.Repository,
	exactTag string,
) error {
	if err := verifyDigestResolution(ctx, repo, built.Index); err != nil {
		rep.Steps = append(rep.Steps, step{Name: "finalize-refuses-missing-digest", OK: false, Detail: err.Error()})
		return err
	}
	rep.Steps = append(rep.Steps, step{
		Name:   "finalize-reresolves-published-digest",
		OK:     true,
		Detail: built.Index.Digest.String(),
	})

	tags := []string{exactTag, majorMinor(built.Version), major(built.Version), "latest"}
	if err := commitTags(ctx, repo, built.Index, tags); err != nil {
		rep.Steps = append(rep.Steps, step{Name: "serial-verified-tag-commit", OK: false, Detail: err.Error()})
		return err
	}
	rep.Steps = append(rep.Steps, step{
		Name:   "serial-verified-tag-commit",
		OK:     true,
		Detail: fmt.Sprintf("%v", tags),
	})

	if err := commitTags(ctx, repo, built.Index, []string{exactTag}); err != nil {
		rep.Steps = append(rep.Steps, step{Name: "retag-same-digest-accepted", OK: false, Detail: err.Error()})
		return err
	}
	rep.Steps = append(rep.Steps, step{Name: "retag-same-digest-accepted", OK: true})

	return nil
}

// majorMinor returns the MAJOR.MINOR channel for a stable version.
func majorMinor(version string) string {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return version
	}
	return parts[0] + "." + parts[1]
}

// major returns the MAJOR channel for a stable version.
func major(version string) string {
	return strings.Split(version, ".")[0]
}

// fetchVersionAnnotation reads the version annotation from a pushed index.
func fetchVersionAnnotation(ctx context.Context, repo *remote.Repository, desc v1.Descriptor) (string, error) {
	reader, err := repo.Fetch(ctx, desc)
	if err != nil {
		return "", fmt.Errorf("fetch index: %w", err)
	}
	defer reader.Close()

	var index v1.Index
	if err := json.NewDecoder(reader).Decode(&index); err != nil {
		return "", fmt.Errorf("decode index: %w", err)
	}
	return index.Annotations[v1.AnnotationVersion], nil
}

// detectExactTagDrift reports whether the exact tag points somewhere other than
// the expected descriptor.
func detectExactTagDrift(
	ctx context.Context,
	repo *remote.Repository,
	tag string,
	expected v1.Descriptor,
) (bool, error) {
	desc, class, err := resolveState(ctx, repo, tag)
	if err != nil {
		return false, err
	}
	if class != classPresent {
		return false, fmt.Errorf("exact tag classified %s", class)
	}
	return desc.Digest != expected.Digest, nil
}

// emit writes the report as one JSON document on stdout.
func emit(rep *report) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(rep)
}
