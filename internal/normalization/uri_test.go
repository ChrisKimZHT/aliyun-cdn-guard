package normalization

import (
	"aliyun-cdn-guard/internal/config"
	"testing"
)

func TestURI(t *testing.T) {
	cases := []struct {
		name, uri, param, mode, want string
		ignored                      map[string]struct{}
	}{
		{"empty", "", "", "keep", "/", nil},
		{"parameter fallback", "/a", "?x=1", "keep", "/a?x=1", nil},
		{"uri wins", "/a?x=1", "y=2", "keep", "/a?x=1", nil},
		{"ignore all", "/a?x=1", "", "ignore_all", "/a", nil},
		{"ignore selected", "/a?x=1&keep=2&x=3", "", "ignore_selected", "/a?keep=2", map[string]struct{}{"x": {}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := URI(tc.uri, tc.param, config.URIConfig{QueryMode: tc.mode, IgnoredNames: tc.ignored})
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
