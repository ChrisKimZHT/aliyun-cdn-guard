package normalization

import (
	"net/url"
	"strings"

	"aliyun-cdn-guard/internal/config"
)

func URI(rawURI, uriParam string, cfg config.URIConfig) string {
	if rawURI == "" {
		rawURI = "/"
	}
	u, err := url.Parse(rawURI)
	if err != nil {
		return rawURI
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	query := u.RawQuery
	if query == "" {
		query = strings.TrimPrefix(uriParam, "?")
	}
	switch cfg.QueryMode {
	case "ignore_all":
		query = ""
	case "ignore_selected":
		if query != "" {
			parts := strings.Split(query, "&")
			kept := parts[:0]
			for _, part := range parts {
				key := part
				if i := strings.IndexByte(part, '='); i >= 0 {
					key = part[:i]
				}
				decoded, err := url.QueryUnescape(key)
				if err != nil {
					decoded = key
				}
				if _, ignored := cfg.IgnoredNames[decoded]; !ignored {
					kept = append(kept, part)
				}
			}
			query = strings.Join(kept, "&")
		}
	}
	if query == "" {
		return path
	}
	return path + "?" + query
}
