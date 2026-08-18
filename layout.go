package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/oci"
)

// platform names one of the two architectures the release contract fixes
// (inventory invariant 6: exactly linux/amd64 and linux/arm64).
type platform struct {
	// arch is the OCI architecture string.
	arch string
	// apkArch is the Alpine/Melange architecture name used in SBOM filenames.
	apkArch string
}

// platforms is the fixed two-platform set the OCI publisher requires.
var platforms = []platform{
	{arch: "amd64", apkArch: "x86_64"},
	{arch: "arm64", apkArch: "aarch64"},
}

// builtLayout describes a synthetic OCI layout on disk plus the digests a
// publisher must carry forward.
type builtLayout struct {
	// Dir is the OCI layout root.
	Dir string
	// Index is the descriptor of the image index.
	Index v1.Descriptor
	// IndexBytes is the exact serialized index the digest was computed over
	// (inventory OP-06 hashes exact index bytes; never re-marshal).
	IndexBytes []byte
	// Manifests maps architecture to its platform manifest descriptor.
	Manifests map[string]v1.Descriptor
	// SBOMPaths maps apk architecture to a written SBOM file.
	SBOMPaths map[string]string
	// Version is the release version annotation carried on the index.
	Version string
}

// buildLayout writes a synthetic two-platform OCI layout mirroring the shape of
// real apko output: one image manifest per architecture, each with a config and
// a single layer, collected under one image index carrying the release version
// annotation. It deliberately does not run melange/apko: this spike proves
// registry semantics, not packaging fidelity.
func buildLayout(ctx context.Context, root, version string) (*builtLayout, error) {
	dir := filepath.Join(root, "oci-layout")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create layout dir: %w", err)
	}

	store, err := oci.New(dir)
	if err != nil {
		return nil, fmt.Errorf("open oci store: %w", err)
	}

	built := &builtLayout{
		Dir:       dir,
		Manifests: make(map[string]v1.Descriptor, len(platforms)),
		SBOMPaths: make(map[string]string, len(platforms)),
		Version:   version,
	}

	indexManifests := make([]v1.Descriptor, 0, len(platforms))

	for _, plat := range platforms {
		manifestDesc, sbomPath, err := buildPlatform(ctx, store, root, version, plat)
		if err != nil {
			return nil, err
		}
		built.Manifests[plat.arch] = manifestDesc
		built.SBOMPaths[plat.apkArch] = sbomPath
		indexManifests = append(indexManifests, manifestDesc)
	}

	index := v1.Index{
		Versioned:   specs.Versioned{SchemaVersion: 2},
		MediaType:   v1.MediaTypeImageIndex,
		Manifests:   indexManifests,
		Annotations: map[string]string{v1.AnnotationVersion: version},
	}
	indexBytes, err := json.Marshal(index)
	if err != nil {
		return nil, fmt.Errorf("marshal index: %w", err)
	}
	indexDesc := content.NewDescriptorFromBytes(v1.MediaTypeImageIndex, indexBytes)
	if err := store.Push(ctx, indexDesc, bytes.NewReader(indexBytes)); err != nil {
		return nil, fmt.Errorf("push index: %w", err)
	}
	if err := store.Tag(ctx, indexDesc, indexDesc.Digest.String()); err != nil {
		return nil, fmt.Errorf("tag index in layout: %w", err)
	}

	built.Index = indexDesc
	built.IndexBytes = indexBytes

	return built, nil
}

// buildPlatform writes one architecture's layer, config, and manifest into the
// layout and returns the manifest descriptor plus the SBOM path for that
// architecture.
func buildPlatform(
	ctx context.Context,
	store *oci.Store,
	root, version string,
	plat platform,
) (v1.Descriptor, string, error) {
	layer := []byte(fmt.Sprintf("canonical application bytes for %s %s\n", plat.arch, version))
	layerDesc := content.NewDescriptorFromBytes(v1.MediaTypeImageLayer, layer)
	if err := store.Push(ctx, layerDesc, bytes.NewReader(layer)); err != nil {
		return v1.Descriptor{}, "", fmt.Errorf("push layer %s: %w", plat.arch, err)
	}

	config := v1.Image{
		Platform: v1.Platform{OS: "linux", Architecture: plat.arch},
		Config:   v1.ImageConfig{Entrypoint: []string{"/usr/bin/release-cli"}, User: "65532"},
		RootFS:   v1.RootFS{Type: "layers", DiffIDs: []digest.Digest{layerDesc.Digest}},
	}
	configBytes, err := json.Marshal(config)
	if err != nil {
		return v1.Descriptor{}, "", fmt.Errorf("marshal config %s: %w", plat.arch, err)
	}
	configDesc := content.NewDescriptorFromBytes(v1.MediaTypeImageConfig, configBytes)
	if err := store.Push(ctx, configDesc, bytes.NewReader(configBytes)); err != nil {
		return v1.Descriptor{}, "", fmt.Errorf("push config %s: %w", plat.arch, err)
	}

	manifest := v1.Manifest{
		Versioned:   specs.Versioned{SchemaVersion: 2},
		MediaType:   v1.MediaTypeImageManifest,
		Config:      configDesc,
		Layers:      []v1.Descriptor{layerDesc},
		Annotations: map[string]string{v1.AnnotationVersion: version},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return v1.Descriptor{}, "", fmt.Errorf("marshal manifest %s: %w", plat.arch, err)
	}
	manifestDesc := content.NewDescriptorFromBytes(v1.MediaTypeImageManifest, manifestBytes)
	if err := store.Push(ctx, manifestDesc, bytes.NewReader(manifestBytes)); err != nil {
		return v1.Descriptor{}, "", fmt.Errorf("push manifest %s: %w", plat.arch, err)
	}
	manifestDesc.Platform = &v1.Platform{OS: "linux", Architecture: plat.arch}

	sbomPath := filepath.Join(root, fmt.Sprintf("sbom-%s.spdx.json", plat.apkArch))
	// Minimal but schema-valid SPDX 2.3: actions/attest rejects anything that is
	// not recognizably SPDX or CycloneDX JSON.
	sbom := map[string]any{
		"spdxVersion":       "SPDX-2.3",
		"dataLicense":       "CC0-1.0",
		"SPDXID":            "SPDXRef-DOCUMENT",
		"name":              fmt.Sprintf("release-cli-%s-%s", version, plat.apkArch),
		"documentNamespace": fmt.Sprintf("https://spike.invalid/release-cli/%s/%s", version, plat.apkArch),
		"creationInfo": map[string]any{
			"created":  "2026-08-18T00:00:00Z",
			"creators": []string{"Tool: release-cli-spike"},
		},
		"documentDescribes": []string{"SPDXRef-Package-application"},
		"packages": []map[string]any{
			{
				"SPDXID":           "SPDXRef-Package-application",
				"name":             "release-cli",
				"versionInfo":      version + "-r0",
				"downloadLocation": "NOASSERTION",
				"licenseConcluded": "NOASSERTION",
				"licenseDeclared":  "NOASSERTION",
				"copyrightText":    "NOASSERTION",
				"filesAnalyzed":    false,
			},
		},
		"relationships": []map[string]string{
			{
				"spdxElementId":      "SPDXRef-DOCUMENT",
				"relationshipType":   "DESCRIBES",
				"relatedSpdxElement": "SPDXRef-Package-application",
			},
		},
	}
	sbomBytes, err := json.MarshalIndent(sbom, "", "  ")
	if err != nil {
		return v1.Descriptor{}, "", fmt.Errorf("marshal sbom %s: %w", plat.apkArch, err)
	}
	if err := os.WriteFile(sbomPath, sbomBytes, 0o644); err != nil {
		return v1.Descriptor{}, "", fmt.Errorf("write sbom %s: %w", plat.apkArch, err)
	}

	return manifestDesc, sbomPath, nil
}
