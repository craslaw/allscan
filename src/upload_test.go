package main

import (
	"strings"
	"testing"
)

func TestExtractProductName(t *testing.T) {
	tests := []struct {
		name    string
		repoURL string
		want    string
	}{
		{
			name:    "standard GitHub HTTPS URL",
			repoURL: "https://github.com/your-org/my-repo",
			want:    "your-org/my-repo",
		},
		{
			name:    "GitHub URL with .git suffix",
			repoURL: "https://github.com/your-org/my-repo.git",
			want:    "your-org/my-repo",
		},
		{
			name:    "different org and repo",
			repoURL: "https://github.com/acme-corp/scanner-tool",
			want:    "acme-corp/scanner-tool",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractProductName(tt.repoURL)
			if got != tt.want {
				t.Errorf("extractProductName(%q) = %q, want %q", tt.repoURL, got, tt.want)
			}
		})
	}
}

func TestUploadRequestBuilder_Build(t *testing.T) {
	t.Run("successful build with all fields", func(t *testing.T) {
		builder := BuildUploadRequest().
			WithEndpoint("https://example.com/api/v2/import-scan/").
			WithFile(strings.NewReader("test data"), "test.json").
			WithAuthToken("mytoken").
			AddFields(map[string]string{"scan_type": "Grype Scan"})

		req, err := builder.Build()
		if err != nil {
			t.Fatalf("Build() error = %v", err)
		}
		if req.Header.Get("Authorization") != "Token mytoken" {
			t.Errorf("Authorization = %q, want %q", req.Header.Get("Authorization"), "Token mytoken")
		}
		ct := req.Header.Get("Content-Type")
		if !strings.Contains(ct, "multipart/form-data") {
			t.Errorf("Content-Type = %q, want to contain %q", ct, "multipart/form-data")
		}
		if req.Method != "POST" {
			t.Errorf("Method = %q, want %q", req.Method, "POST")
		}
		if req.URL.String() != "https://example.com/api/v2/import-scan/" {
			t.Errorf("URL = %q, want %q", req.URL.String(), "https://example.com/api/v2/import-scan/")
		}
	})

	t.Run("missing endpoint returns error", func(t *testing.T) {
		builder := BuildUploadRequest().
			WithFile(strings.NewReader("test"), "test.json")

		_, err := builder.Build()
		if err == nil {
			t.Error("Build() expected error for missing endpoint, got nil")
		}
	})

	t.Run("missing file returns error", func(t *testing.T) {
		builder := BuildUploadRequest().
			WithEndpoint("https://example.com/api")

		_, err := builder.Build()
		if err == nil {
			t.Error("Build() expected error for missing file, got nil")
		}
	})

	t.Run("no auth token omits header", func(t *testing.T) {
		builder := BuildUploadRequest().
			WithEndpoint("https://example.com/api").
			WithFile(strings.NewReader("test"), "test.json")

		req, err := builder.Build()
		if err != nil {
			t.Fatalf("Build() error = %v", err)
		}
		if req.Header.Get("Authorization") != "" {
			t.Errorf("Authorization = %q, want empty", req.Header.Get("Authorization"))
		}
	})
}
