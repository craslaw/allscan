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
