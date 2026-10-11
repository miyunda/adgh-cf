package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"strings"
)

type DomainGroup struct {
	ID      string        `json:"id"`
	Primary string        `json:"primary"`
	Members []GroupMember `json:"members"`
}
type GroupMember struct {
	Domain               string  `json:"domain"`
	URL                  string  `json:"url"`
	Mode                 string  `json:"mode"`
	ExpectedStatusCodes  []int   `json:"expectedStatusCodes,omitempty"`
	ExpectedBodyContains *string `json:"expectedBodyContains,omitempty"`
}

func rejectNull(value any) error {
	switch v := value.(type) {
	case nil:
		return fmt.Errorf("configuration values cannot be null")
	case map[string]any:
		for k, x := range v {
			if err := rejectNull(x); err != nil {
				return fmt.Errorf("%s: %w", k, err)
			}
		}
	case []any:
		for _, x := range v {
			if err := rejectNull(x); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseConfig(data []byte, base string) (Config, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return Config{}, fmt.Errorf("config JSON: %w", err)
	}
	// encoding/json accepts case-insensitive field aliases; the version boundary
	// requires exact names so aliases cannot bypass presence/mixing checks.
	if err := exactConfigKeys(fields, reflect.TypeOf(Config{})); err != nil {
		return Config{}, err
	}
	version := 1
	if raw, ok := fields["schemaVersion"]; ok {
		if err := json.Unmarshal(raw, &version); err != nil || bytes.Equal(raw, []byte("null")) {
			return Config{}, fmt.Errorf("schemaVersion must be 1 or 2")
		}
	}
	if version != 1 && version != 2 {
		return Config{}, fmt.Errorf("unsupported schemaVersion %d", version)
	}
	if version == 1 {
		for _, k := range []string{"groups", "maxRequestsPerGroup", "maxRunSeconds"} {
			if _, ok := fields[k]; ok {
				return Config{}, fmt.Errorf("%s requires schemaVersion 2", k)
			}
		}
		return parseLegacyConfig(data, base)
	}
	var generic any
	if err := json.Unmarshal(data, &generic); err != nil {
		return Config{}, err
	}
	if err := rejectNull(generic); err != nil {
		return Config{}, err
	}
	for _, k := range []string{"domain", "healthPath", "healthMode", "port", "expectedStatusCodes", "expectedBodyContains"} {
		if _, ok := fields[k]; ok {
			return Config{}, fmt.Errorf("v2 does not accept top-level %s; use groups.members", k)
		}
	}
	if _, ok := fields["stateFile"]; !ok {
		return Config{}, fmt.Errorf("v2 requires an explicit separate stateFile")
	}
	var model Config
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&model); err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	if len(model.Groups) < 1 || len(model.Groups) > 4 {
		return Config{}, fmt.Errorf("groups count %d; allowed 1..4", len(model.Groups))
	}
	ids, domains := map[string]bool{}, map[string]bool{}
	total := 0
	for i := range model.Groups {
		g := &model.Groups[i]
		if !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`).MatchString(g.ID) || ids[g.ID] {
			return Config{}, fmt.Errorf("group id %q must be unique and match [a-z0-9][a-z0-9-]{0,63}", g.ID)
		}
		ids[g.ID] = true
		if len(g.Members) < 1 || len(g.Members) > 8 {
			return Config{}, fmt.Errorf("group %s member count %d; allowed 1..8", g.ID, len(g.Members))
		}
		g.Primary = normalizeDomain(g.Primary)
		primary := false
		for j := range g.Members {
			m := &g.Members[j]
			m.Domain = normalizeDomain(m.Domain)
			if !validDomain(m.Domain) || domains[m.Domain] {
				return Config{}, fmt.Errorf("group %s: invalid or duplicate domain %q", g.ID, m.Domain)
			}
			domains[m.Domain] = true
			total++
			if m.Domain == g.Primary {
				primary = true
			}
			u, err := url.Parse(m.URL)
			if err != nil || u.Scheme != "https" || normalizeDomain(u.Hostname()) != m.Domain || (u.Port() != "" && u.Port() != "443") || u.User != nil || u.Fragment != "" || strings.HasSuffix(u.Host, ":") || strings.ContainsAny(m.URL, "\\#") || strings.IndexFunc(m.URL, func(r rune) bool { return r <= 32 || r == 127 }) >= 0 {
				return Config{}, fmt.Errorf("group %s member %s: URL must be same-domain HTTPS on port 443 without credentials, fragment or unsafe characters", g.ID, m.Domain)
			}
			u.Host = m.Domain
			if u.Path == "" {
				u.Path = "/"
			}
			m.URL = u.String()
			if m.Mode == "" {
				m.Mode = "https"
			}
			switch m.Mode {
			case "https", "openbao":
				// Presence, including an empty list, must not imply an ignored condition.
				var rawGroups []struct {
					Members []map[string]json.RawMessage `json:"members"`
				}
				_ = json.Unmarshal(fields["groups"], &rawGroups)
				for _, k := range []string{"expectedStatusCodes", "expectedBodyContains"} {
					if _, ok := rawGroups[i].Members[j][k]; ok {
						return Config{}, fmt.Errorf("%s only accepts expected response fields in http mode", m.Domain)
					}
				}
			case "http":
				if len(m.ExpectedStatusCodes) < 1 || len(m.ExpectedStatusCodes) > 5 {
					return Config{}, fmt.Errorf("%s requires 1..5 expectedStatusCodes", m.Domain)
				}
				for _, code := range m.ExpectedStatusCodes {
					if code < 200 || code > 299 {
						return Config{}, fmt.Errorf("%s expectedStatusCodes must be 200..299", m.Domain)
					}
				}
				if m.ExpectedBodyContains != nil && (strings.TrimSpace(*m.ExpectedBodyContains) == "" || len(*m.ExpectedBodyContains) > 256) {
					return Config{}, fmt.Errorf("%s expectedBodyContains must be nonempty and at most 256 bytes", m.Domain)
				}
			default:
				return Config{}, fmt.Errorf("%s mode must be https, http or openbao", m.Domain)
			}
		}
		if !primary {
			return Config{}, fmt.Errorf("group %s primary must reference a member", g.ID)
		}
	}
	if total > 16 {
		return Config{}, fmt.Errorf("total domain count %d; allowed at most 16", total)
	}
	for _, k := range []string{"groups", "maxRequestsPerGroup", "maxRunSeconds", "schemaVersion"} {
		delete(fields, k)
	}
	fields["domain"] = json.RawMessage(`"example.com"`)
	sanitized, _ := json.Marshal(fields)
	c, err := parseLegacyConfig(sanitized, base)
	if err != nil {
		return c, err
	}
	c.SchemaVersion, c.Groups = 2, model.Groups
	c.Domain, c.HealthPath, c.HealthMode = "", "", ""
	c.MaxRequestsPerGroup, c.MaxRunSeconds = 160, 1800
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(data, &raw)
	if _, ok := raw["maxRequestsPerGroup"]; ok {
		c.MaxRequestsPerGroup = model.MaxRequestsPerGroup
	}
	if _, ok := raw["maxRunSeconds"]; ok {
		c.MaxRunSeconds = model.MaxRunSeconds
	}
	if c.MaxRequestsPerGroup < 1 || c.MaxRequestsPerGroup > 1000 {
		return c, fmt.Errorf("maxRequestsPerGroup must be 1..1000")
	}
	if c.MaxRunSeconds < 60 || c.MaxRunSeconds > 7200 {
		return c, fmt.Errorf("maxRunSeconds must be 60..7200")
	}
	return c, nil
}

func normalizeDomain(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }
func validDomain(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return false
	}
	label := regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	for _, part := range strings.Split(s, ".") {
		if !label.MatchString(part) {
			return false
		}
	}
	return true
}
func memberConfig(c Config, m GroupMember) Config {
	c.Domain, c.HealthMode = m.Domain, m.Mode
	u, _ := url.Parse(m.URL)
	c.HealthPath = u.RequestURI()
	c.ExpectedStatusCodes = m.ExpectedStatusCodes
	c.ExpectedBodyContains = ""
	if m.ExpectedBodyContains != nil {
		c.ExpectedBodyContains = *m.ExpectedBodyContains
	}
	return c
}

func exactConfigKeys(fields map[string]json.RawMessage, typ reflect.Type) error {
	allowed := map[string]reflect.Type{}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		if tag != "" && tag != "-" {
			allowed[tag] = f.Type
		}
	}
	for key, raw := range fields {
		ft, ok := allowed[key]
		if !ok {
			return fmt.Errorf("unknown configuration field %q", key)
		}
		if ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.Struct {
			var children []map[string]json.RawMessage
			if err := json.Unmarshal(raw, &children); err != nil {
				return fmt.Errorf("%s must be an array of objects", key)
			}
			for _, child := range children {
				if err := exactConfigKeys(child, ft.Elem()); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
