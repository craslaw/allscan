package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	packageurl "github.com/package-url/packageurl-go"
)

func TestNormalizeRepoURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"clean https", "https://github.com/foo/bar", "https://github.com/foo/bar"},
		{"git+https", "git+https://github.com/foo/bar.git", "https://github.com/foo/bar"},
		{"ssh prefix", "ssh://github.com/foo/bar.git", "https://github.com/foo/bar"},
		{"git protocol", "git://github.com/foo/bar.git", "https://github.com/foo/bar"},
		{"git@ scp style", "git@github.com:foo/bar.git", "https://github.com/foo/bar"},
		{"trailing slash", "https://github.com/foo/bar/", "https://github.com/foo/bar"},
		{"trailing .git and slash", "https://github.com/foo/bar.git/", "https://github.com/foo/bar"},
		{"no transform needed", "https://gitlab.com/foo/bar", "https://gitlab.com/foo/bar"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeRepoURL(tt.input)
			if got != tt.want {
				t.Errorf("normalizeRepoURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestResolvePURL(t *testing.T) {
	tests := []struct {
		name        string
		purl        string
		wantURL     string
		wantVersion string
		wantErr     bool
		wantWarns   bool
	}{
		{
			name:        "github type",
			purl:        "pkg:github/gin-gonic/gin@v1.10.0",
			wantURL:     "https://github.com/gin-gonic/gin",
			wantVersion: "v1.10.0",
		},
		{
			name:        "github type without version",
			purl:        "pkg:github/gin-gonic/gin",
			wantURL:     "https://github.com/gin-gonic/gin",
			wantVersion: "",
		},
		{
			name:        "golang github module",
			purl:        "pkg:golang/github.com/gin-gonic/gin@v1.10.0",
			wantURL:     "https://github.com/gin-gonic/gin",
			wantVersion: "v1.10.0",
		},
		{
			name:        "golang deep module path",
			purl:        "pkg:golang/github.com/aws/aws-sdk-go-v2/service/s3@v1.0.0",
			wantURL:     "https://github.com/aws/aws-sdk-go-v2",
			wantVersion: "v1.0.0",
		},
		{
			name:        "golang non-github module",
			purl:        "pkg:golang/golang.org/x/text@v0.14.0",
			wantURL:     "",
			wantVersion: "v0.14.0",
			wantWarns:   true,
		},
		{
			name:        "repository_url qualifier",
			purl:        "pkg:docker/nginx@1.25?repository_url=https://github.com/nginx/nginx",
			wantURL:     "https://github.com/nginx/nginx",
			wantVersion: "1.25",
		},
		{
			name:        "unsupported type without qualifier",
			purl:        "pkg:docker/nginx@1.25",
			wantURL:     "",
			wantVersion: "1.25",
			wantWarns:   true,
		},
		{
			name:    "invalid purl",
			purl:    "not-a-purl",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, version, warnings, err := resolvePURL(tt.purl)
			if (err != nil) != tt.wantErr {
				t.Fatalf("resolvePURL(%q) error = %v, wantErr %v", tt.purl, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if url != tt.wantURL {
				t.Errorf("resolvePURL(%q) url = %q, want %q", tt.purl, url, tt.wantURL)
			}
			if version != tt.wantVersion {
				t.Errorf("resolvePURL(%q) version = %q, want %q", tt.purl, version, tt.wantVersion)
			}
			if tt.wantWarns && len(warnings) == 0 {
				t.Errorf("resolvePURL(%q) expected warnings but got none", tt.purl)
			}
			if !tt.wantWarns && len(warnings) > 0 {
				t.Errorf("resolvePURL(%q) unexpected warnings: %v", tt.purl, warnings)
			}
		})
	}
}

func TestResolveNPMRepo(t *testing.T) {
	tests := []struct {
		name      string
		pkg       string
		namespace string
		response  string
		status    int
		wantURL   string
		wantWarns bool
	}{
		{
			name:     "success",
			pkg:      "express",
			response: `{"repository":{"type":"git","url":"git+https://github.com/expressjs/express.git"}}`,
			status:   http.StatusOK,
			wantURL:  "https://github.com/expressjs/express",
		},
		{
			name:      "scoped package",
			pkg:       "core",
			namespace: "@angular",
			response:  `{"repository":{"type":"git","url":"https://github.com/angular/angular.git"}}`,
			status:    http.StatusOK,
			wantURL:   "https://github.com/angular/angular",
		},
		{
			name:      "404",
			pkg:       "nonexistent",
			status:    http.StatusNotFound,
			response:  `{"error":"not found"}`,
			wantWarns: true,
		},
		{
			name:      "missing repository field",
			pkg:       "no-repo",
			response:  `{"name":"no-repo"}`,
			status:    http.StatusOK,
			wantWarns: true,
		},
		{
			name:      "bad json",
			pkg:       "bad",
			response:  `{invalid`,
			status:    http.StatusOK,
			wantWarns: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			purl := packageurl.PackageURL{Name: tt.pkg, Namespace: tt.namespace}
			url, warnings := resolveNPMRepo(purl, server.URL)
			if url != tt.wantURL {
				t.Errorf("resolveNPMRepo() url = %q, want %q", url, tt.wantURL)
			}
			if tt.wantWarns && len(warnings) == 0 {
				t.Error("expected warnings but got none")
			}
			if !tt.wantWarns && len(warnings) > 0 {
				t.Errorf("unexpected warnings: %v", warnings)
			}
		})
	}
}

func TestResolvePyPIRepo(t *testing.T) {
	tests := []struct {
		name      string
		pkg       string
		response  string
		status    int
		wantURL   string
		wantWarns bool
	}{
		{
			name:     "success with Source key",
			pkg:      "requests",
			response: `{"info":{"project_urls":{"Source":"https://github.com/psf/requests"}}}`,
			status:   http.StatusOK,
			wantURL:  "https://github.com/psf/requests",
		},
		{
			name:     "success with Repository key",
			pkg:      "flask",
			response: `{"info":{"project_urls":{"Repository":"https://github.com/pallets/flask"}}}`,
			status:   http.StatusOK,
			wantURL:  "https://github.com/pallets/flask",
		},
		{
			name:      "404",
			pkg:       "nonexistent",
			status:    http.StatusNotFound,
			response:  `{"message":"Not Found"}`,
			wantWarns: true,
		},
		{
			name:      "no github url in project_urls",
			pkg:       "internal-pkg",
			response:  `{"info":{"project_urls":{"Homepage":"https://example.com"}}}`,
			status:    http.StatusOK,
			wantWarns: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			purl := packageurl.PackageURL{Name: tt.pkg}
			url, warnings := resolvePyPIRepo(purl, server.URL)
			if url != tt.wantURL {
				t.Errorf("resolvePyPIRepo() url = %q, want %q", url, tt.wantURL)
			}
			if tt.wantWarns && len(warnings) == 0 {
				t.Error("expected warnings but got none")
			}
			if !tt.wantWarns && len(warnings) > 0 {
				t.Errorf("unexpected warnings: %v", warnings)
			}
		})
	}
}

func TestResolveCargoRepo(t *testing.T) {
	tests := []struct {
		name      string
		pkg       string
		response  string
		status    int
		wantURL   string
		wantWarns bool
	}{
		{
			name:     "success",
			pkg:      "serde",
			response: `{"crate":{"repository":"https://github.com/serde-rs/serde"}}`,
			status:   http.StatusOK,
			wantURL:  "https://github.com/serde-rs/serde",
		},
		{
			name:      "404",
			pkg:       "nonexistent",
			status:    http.StatusNotFound,
			response:  `{"errors":[{"detail":"not found"}]}`,
			wantWarns: true,
		},
		{
			name:      "missing repository",
			pkg:       "no-repo",
			response:  `{"crate":{"name":"no-repo"}}`,
			status:    http.StatusOK,
			wantWarns: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			purl := packageurl.PackageURL{Name: tt.pkg}
			url, warnings := resolveCargoRepo(purl, server.URL)
			if url != tt.wantURL {
				t.Errorf("resolveCargoRepo() url = %q, want %q", url, tt.wantURL)
			}
			if tt.wantWarns && len(warnings) == 0 {
				t.Error("expected warnings but got none")
			}
			if !tt.wantWarns && len(warnings) > 0 {
				t.Errorf("unexpected warnings: %v", warnings)
			}
		})
	}
}

func TestResolveGemRepo(t *testing.T) {
	tests := []struct {
		name      string
		pkg       string
		response  string
		status    int
		wantURL   string
		wantWarns bool
	}{
		{
			name:     "success",
			pkg:      "rails",
			response: `{"source_code_uri":"https://github.com/rails/rails"}`,
			status:   http.StatusOK,
			wantURL:  "https://github.com/rails/rails",
		},
		{
			name:      "404",
			pkg:       "nonexistent",
			status:    http.StatusNotFound,
			response:  `This rubygem could not be found.`,
			wantWarns: true,
		},
		{
			name:      "missing source_code_uri",
			pkg:       "no-source",
			response:  `{"name":"no-source"}`,
			status:    http.StatusOK,
			wantWarns: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			purl := packageurl.PackageURL{Name: tt.pkg}
			url, warnings := resolveGemRepo(purl, server.URL)
			if url != tt.wantURL {
				t.Errorf("resolveGemRepo() url = %q, want %q", url, tt.wantURL)
			}
			if tt.wantWarns && len(warnings) == 0 {
				t.Error("expected warnings but got none")
			}
			if !tt.wantWarns && len(warnings) > 0 {
				t.Errorf("unexpected warnings: %v", warnings)
			}
		})
	}
}

func TestResolveVersionTagFromOutput(t *testing.T) {
	lsRemoteOutput := []byte(`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa	refs/tags/openssl-v0.10.74
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb	refs/tags/openssl-v0.10.75
cccccccccccccccccccccccccccccccccccccccc	refs/tags/openssl-v0.10.75^{}
dddddddddddddddddddddddddddddddddddddd	refs/tags/v1.0.0
eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee	refs/tags/v2.0.0
ffffffffffffffffffffffffffffffffffffffff	refs/tags/v2.0.0^{}
`)

	tests := []struct {
		name       string
		version    string
		wantTag    string
		wantHash   string
	}{
		{
			name:     "exact match",
			version:  "v1.0.0",
			wantTag:  "v1.0.0",
			wantHash: "dddddddddddddddddddddddddddddddddddddd",
		},
		{
			name:     "exact match with dereferenced commit",
			version:  "v2.0.0",
			wantTag:  "v2.0.0",
			wantHash: "ffffffffffffffffffffffffffffffffffffffff",
		},
		{
			name:     "v-prefix added automatically",
			version:  "1.0.0",
			wantTag:  "v1.0.0",
			wantHash: "dddddddddddddddddddddddddddddddddddddd",
		},
		{
			name:     "suffix match with dash separator",
			version:  "0.10.75",
			wantTag:  "openssl-v0.10.75",
			wantHash: "cccccccccccccccccccccccccccccccccccccccc", // dereferenced
		},
		{
			name:     "suffix match version already has v prefix",
			version:  "v0.10.75",
			wantTag:  "openssl-v0.10.75",
			wantHash: "cccccccccccccccccccccccccccccccccccccccc",
		},
		{
			name:    "no match",
			version: "9.9.9",
			wantTag: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tag, hash := resolveVersionTagFromOutput("https://example.com/repo", tt.version, lsRemoteOutput)
			if tag != tt.wantTag {
				t.Errorf("tag = %q, want %q", tag, tt.wantTag)
			}
			if tt.wantHash != "" && hash != tt.wantHash {
				t.Errorf("hash = %q, want %q", hash, tt.wantHash)
			}
		})
	}
}

func TestResolveVersionTagFromOutput_SlashSeparator(t *testing.T) {
	lsRemoteOutput := []byte(`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa	refs/tags/crate/0.5.0
`)
	tag, hash := resolveVersionTagFromOutput("https://example.com/repo", "0.5.0", lsRemoteOutput)
	if tag != "crate/0.5.0" {
		t.Errorf("tag = %q, want %q", tag, "crate/0.5.0")
	}
	if hash != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("hash = %q, want full hash", hash)
	}
}

func TestResolveVersionTagFromOutput_Empty(t *testing.T) {
	tag, hash := resolveVersionTagFromOutput("https://example.com/repo", "1.0.0", []byte(""))
	if tag != "" || hash != "" {
		t.Errorf("expected empty results, got tag=%q hash=%q", tag, hash)
	}
}

func TestResolvePURLEntries(t *testing.T) {
	tests := []struct {
		name     string
		input    []RepositoryConfig
		wantLen  int
		wantURLs []string
	}{
		{
			name: "url entries pass through unchanged",
			input: []RepositoryConfig{
				{URL: "https://github.com/foo/bar", Branch: "main"},
			},
			wantLen:  1,
			wantURLs: []string{"https://github.com/foo/bar"},
		},
		{
			name: "github purl resolved",
			input: []RepositoryConfig{
				{PURL: "pkg:github/gin-gonic/gin@v1.10.0"},
			},
			wantLen:  1,
			wantURLs: []string{"https://github.com/gin-gonic/gin"},
		},
		{
			name: "mixed url and purl entries",
			input: []RepositoryConfig{
				{URL: "https://github.com/foo/bar", Branch: "main"},
				{PURL: "pkg:github/baz/qux@v2.0.0"},
			},
			wantLen:  2,
			wantURLs: []string{"https://github.com/foo/bar", "https://github.com/baz/qux"},
		},
		{
			name: "unresolvable purl skipped",
			input: []RepositoryConfig{
				{PURL: "pkg:docker/nginx@1.25"},
				{URL: "https://github.com/foo/bar", Branch: "main"},
			},
			wantLen:  1,
			wantURLs: []string{"https://github.com/foo/bar"},
		},
		{
			name: "invalid purl skipped",
			input: []RepositoryConfig{
				{PURL: "not-valid"},
				{URL: "https://github.com/foo/bar", Branch: "main"},
			},
			wantLen:  1,
			wantURLs: []string{"https://github.com/foo/bar"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolvePURLEntries(tt.input)
			if len(result) != tt.wantLen {
				t.Fatalf("resolvePURLEntries() returned %d entries, want %d", len(result), tt.wantLen)
			}
			for i, wantURL := range tt.wantURLs {
				if result[i].URL != wantURL {
					t.Errorf("entry[%d].URL = %q, want %q", i, result[i].URL, wantURL)
				}
			}
		})
	}
}

func TestResolvePURLEntries_VersionFromPURL(t *testing.T) {
	repos := []RepositoryConfig{
		{PURL: "pkg:github/foo/bar@v3.0.0"},
	}
	result := resolvePURLEntries(repos)
	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result))
	}
	// resolvePURLVersion will try git ls-remote (fails for fake URL) and
	// fall back to using the pURL version as a literal tag name
	if result[0].Version != "v3.0.0" {
		t.Errorf("expected version v3.0.0, got %q", result[0].Version)
	}
}

func TestResolvePURLEntries_ExplicitVersionOverride(t *testing.T) {
	repos := []RepositoryConfig{
		{PURL: "pkg:github/foo/bar@v2.0.0", Version: "v1.0.0"},
	}
	result := resolvePURLEntries(repos)
	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result))
	}
	// Explicit version in the YAML should take precedence over pURL version
	if result[0].Version != "v1.0.0" {
		t.Errorf("expected version v1.0.0, got %q", result[0].Version)
	}
}
