package main

import "testing"

func TestParseGitHubURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantOwner string
		wantRepo  string
		wantOk    bool
	}{
		{
			name:      "HTTPS URL",
			url:       "https://github.com/myorg/myrepo",
			wantOwner: "myorg",
			wantRepo:  "myrepo",
			wantOk:    true,
		},
		{
			name:      "HTTPS URL with .git suffix",
			url:       "https://github.com/myorg/myrepo.git",
			wantOwner: "myorg",
			wantRepo:  "myrepo",
			wantOk:    true,
		},
		{
			name:      "SSH URL",
			url:       "git@github.com:myorg/myrepo.git",
			wantOwner: "myorg",
			wantRepo:  "myrepo",
			wantOk:    true,
		},
		{
			name:      "SSH URL without .git",
			url:       "git@github.com:myorg/myrepo",
			wantOwner: "myorg",
			wantRepo:  "myrepo",
			wantOk:    true,
		},
		{
			name:   "non-GitHub URL",
			url:    "https://gitlab.com/myorg/myrepo",
			wantOk: false,
		},
		{
			name:   "empty string",
			url:    "",
			wantOk: false,
		},
		{
			name:      "HTTPS URL with www",
			url:       "https://www.github.com/myorg/myrepo",
			wantOwner: "myorg",
			wantRepo:  "myrepo",
			wantOk:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, ok := parseGitHubURL(tt.url)
			if ok != tt.wantOk {
				t.Errorf("parseGitHubURL(%q) ok = %v, want %v", tt.url, ok, tt.wantOk)
				return
			}
			if ok {
				if owner != tt.wantOwner {
					t.Errorf("owner = %q, want %q", owner, tt.wantOwner)
				}
				if repo != tt.wantRepo {
					t.Errorf("repo = %q, want %q", repo, tt.wantRepo)
				}
			}
		})
	}
}

func TestHasLanguage(t *testing.T) {
	detected := &DetectedLanguages{
		Languages: []string{"go", "python", "javascript"},
	}

	tests := []struct {
		name string
		lang string
		want bool
	}{
		{name: "exact match", lang: "go", want: true},
		{name: "case insensitive Go", lang: "Go", want: true},
		{name: "case insensitive GO", lang: "GO", want: true},
		{name: "not present", lang: "java", want: false},
		{name: "empty string", lang: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detected.hasLanguage(tt.lang)
			if got != tt.want {
				t.Errorf("hasLanguage(%q) = %v, want %v", tt.lang, got, tt.want)
			}
		})
	}
}

func TestHasAnyLanguage(t *testing.T) {
	detected := &DetectedLanguages{
		Languages: []string{"go", "python"},
	}

	tests := []struct {
		name      string
		languages []string
		want      bool
	}{
		{name: "one match", languages: []string{"java", "go"}, want: true},
		{name: "no match", languages: []string{"java", "kotlin"}, want: false},
		{name: "empty search list", languages: []string{}, want: false},
		{name: "nil search list", languages: nil, want: false},
		{name: "all match", languages: []string{"go", "python"}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detected.hasAnyLanguage(tt.languages)
			if got != tt.want {
				t.Errorf("hasAnyLanguage(%v) = %v, want %v", tt.languages, got, tt.want)
			}
		})
	}

	t.Run("empty detected languages", func(t *testing.T) {
		empty := &DetectedLanguages{Languages: []string{}}
		if empty.hasAnyLanguage([]string{"go"}) {
			t.Error("hasAnyLanguage() with empty detected should return false")
		}
	})
}
