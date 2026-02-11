package main

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestRelFromArchiveSubdir(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		entry       string
		subdir      string
		wantRelPath string
		wantOK      bool
	}{
		{
			name:        "nested repository root",
			entry:       "SigmaHQ-sigma-abc123/rules/linux/process_creation/test.yml",
			subdir:      "rules/linux",
			wantRelPath: "process_creation/test.yml",
			wantOK:      true,
		},
		{
			name:        "direct rules path",
			entry:       "rules/linux/file_event/test.yml",
			subdir:      "rules/linux",
			wantRelPath: "file_event/test.yml",
			wantOK:      true,
		},
		{
			name:        "subdir root directory entry",
			entry:       "repo/rules/linux",
			subdir:      "rules/linux",
			wantRelPath: "",
			wantOK:      true,
		},
		{
			name:        "non-matching subdir",
			entry:       "repo/rules/windows/test.yml",
			subdir:      "rules/linux",
			wantRelPath: "",
			wantOK:      false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotRelPath, gotOK := relFromArchiveSubdir(tt.entry, tt.subdir)
			if gotOK != tt.wantOK {
				t.Fatalf("relFromArchiveSubdir() ok = %v, want %v", gotOK, tt.wantOK)
			}
			if gotRelPath != tt.wantRelPath {
				t.Fatalf("relFromArchiveSubdir() rel = %q, want %q", gotRelPath, tt.wantRelPath)
			}
		})
	}
}

func TestSelectAuroraAssetPrefersRenamedTarball(t *testing.T) {
	t.Parallel()

	assets := []githubReleaseAsset{
		{Name: "aurora-linux-v1.2.3-linux-amd64.tar.gz", BrowserDownloadURL: "https://example.test/legacy.tgz"},
		{Name: "aurora-v1.2.3-linux-amd64.zip", BrowserDownloadURL: "https://example.test/new.zip"},
		{Name: "aurora-v1.2.3-linux-amd64.tar.gz", BrowserDownloadURL: "https://example.test/new.tgz"},
	}

	asset, err := selectAuroraAsset(assets, "linux", "amd64", "")
	if err != nil {
		t.Fatalf("selectAuroraAsset() error = %v", err)
	}
	if asset.Name != "aurora-v1.2.3-linux-amd64.tar.gz" {
		t.Fatalf("selectAuroraAsset() picked %q", asset.Name)
	}
}

func TestSelectAuroraAssetFallsBackToLegacyName(t *testing.T) {
	t.Parallel()

	assets := []githubReleaseAsset{
		{Name: "aurora-linux-v1.2.3-linux-amd64.tar.gz", BrowserDownloadURL: "https://example.test/legacy.tgz"},
	}

	asset, err := selectAuroraAsset(assets, "linux", "amd64", "")
	if err != nil {
		t.Fatalf("selectAuroraAsset() error = %v", err)
	}
	if asset.Name != "aurora-linux-v1.2.3-linux-amd64.tar.gz" {
		t.Fatalf("selectAuroraAsset() picked %q", asset.Name)
	}
}

func TestExtractBestBinaryFromTarGzPrefersAurora(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "release.tar.gz")
	outputPath := filepath.Join(tmpDir, "aurora")

	if err := writeTestTarGz(archivePath, map[string]string{
		"opt/aurora-linux/aurora-linux": "legacy-binary",
		"opt/aurora-linux/aurora":       "new-binary",
	}); err != nil {
		t.Fatalf("writeTestTarGz() error = %v", err)
	}

	entryName, err := extractBestBinaryFromTarGz(archivePath, outputPath, []string{"aurora", "aurora-linux"})
	if err != nil {
		t.Fatalf("extractBestBinaryFromTarGz() error = %v", err)
	}
	if entryName != "opt/aurora-linux/aurora" {
		t.Fatalf("extractBestBinaryFromTarGz() entry = %q", entryName)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(content) != "new-binary" {
		t.Fatalf("output binary content = %q", string(content))
	}
}

func writeTestTarGz(archivePath string, files map[string]string) error {
	f, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gzw := gzip.NewWriter(f)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()

	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0o755,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			return err
		}
	}

	return nil
}
