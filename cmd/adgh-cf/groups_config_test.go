package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func groupConfigData(sizes ...int) map[string]any {
	groups := []any{}
	for i, n := range sizes {
		members := []any{}
		for j := 0; j < n; j++ {
			domain := fmt.Sprintf("m%d-g%d.example.com", j, i)
			members = append(members, map[string]any{"domain": domain, "url": "https://" + domain + "/"})
		}
		groups = append(groups, map[string]any{"id": fmt.Sprintf("g%d", i), "primary": fmt.Sprintf("m0-g%d.example.com", i), "members": members})
	}
	return map[string]any{"schemaVersion": 2, "candidateFile": "candidates/cloudflare-ipv4.txt", "stateFile": "state/v2.json", "groups": groups}
}
func parseGroupMap(t *testing.T, m map[string]any) (Config, error) {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return parseConfig(data, t.TempDir())
}
func TestGroupConfigBoundsAndCompatibility(t *testing.T) {
	for _, sizes := range [][]int{{8, 8}, {4, 4, 4, 4}, {1}, {8, 4, 3, 1}} {
		c, err := parseGroupMap(t, groupConfigData(sizes...))
		if err != nil || c.Groups[0].Members[0].Mode != "https" || c.MaxRequestsPerGroup != 160 {
			t.Fatalf("%v: %+v %v", sizes, c, err)
		}
	}
	for _, sizes := range [][]int{{}, {0}, {9}, {8, 8, 1}, {1, 1, 1, 1, 1}} {
		if _, err := parseGroupMap(t, groupConfigData(sizes...)); err == nil {
			t.Fatalf("accepted %v", sizes)
		}
	}
	for _, version := range []string{"", `"schemaVersion":1,`} {
		c, err := parseConfig([]byte(`{`+version+`"domain":"bao.example.com","candidateFile":"ips.txt"}`), ".")
		if err != nil || c.HealthMode != "openbao" {
			t.Fatal(c, err)
		}
	}
	if _, err := parseConfig([]byte(`{"schemaVersion":1,"domain":"a.example.com","candidateFile":"ips","healthMode":"http","healthPath":"/","expectedStatusCodes":[200]}`), "."); err == nil {
		t.Fatal("v1 http weakened")
	}
}
func TestGroupConfigRejectsUnsafeFields(t *testing.T) {
	cases := []struct {
		name string
		edit func(map[string]any)
	}{
		{"version", func(m map[string]any) { m["schemaVersion"] = 3 }},
		{"mixed", func(m map[string]any) { m["domain"] = "a.example.com" }},
		{"unknown", func(m map[string]any) { m["surprise"] = true }},
		{"state", func(m map[string]any) { delete(m, "stateFile") }},
		{"budget", func(m map[string]any) { m["maxRequestsPerGroup"] = 0 }},
		{"time", func(m map[string]any) { m["maxRunSeconds"] = 7201 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := groupConfigData(1)
			tc.edit(m)
			if _, err := parseGroupMap(t, m); err == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
	for _, url := range []string{"http://m0-g0.example.com/", "https://other.example.com/", "https://m0-g0.example.com:444/", "https://user@m0-g0.example.com/", "https://m0-g0.example.com/#", "https://m0-g0.example.com/\\path", "https://m0-g0.example.com/\n"} {
		m := groupConfigData(1)
		member := m["groups"].([]any)[0].(map[string]any)["members"].([]any)[0].(map[string]any)
		member["url"] = url
		if _, err := parseGroupMap(t, m); err == nil {
			t.Fatalf("accepted URL %q", url)
		}
	}
	for _, field := range []string{"mode", "url", "expectedBodyContains", "expectedStatusCodes"} {
		m := groupConfigData(1)
		member := m["groups"].([]any)[0].(map[string]any)["members"].([]any)[0].(map[string]any)
		member[field] = nil
		if _, err := parseGroupMap(t, m); err == nil {
			t.Fatalf("accepted null %s", field)
		}
	}
	m := groupConfigData(2)
	members := m["groups"].([]any)[0].(map[string]any)["members"].([]any)
	members[1].(map[string]any)["domain"] = "M0-G0.EXAMPLE.COM."
	members[1].(map[string]any)["url"] = "https://m0-g0.example.com/"
	if _, err := parseGroupMap(t, m); err == nil {
		t.Fatal("accepted duplicate normalized domain")
	}
}
func TestGroupHTTPConditions(t *testing.T) {
	m := groupConfigData(1)
	member := m["groups"].([]any)[0].(map[string]any)["members"].([]any)[0].(map[string]any)
	member["mode"] = "http"
	member["expectedStatusCodes"] = []int{200}
	if _, err := parseGroupMap(t, m); err != nil {
		t.Fatal(err)
	}
	member["expectedBodyContains"] = ""
	if _, err := parseGroupMap(t, m); err == nil {
		t.Fatal("empty marker accepted")
	}
	delete(member, "expectedBodyContains")
	member["mode"] = "https"
	member["expectedStatusCodes"] = []int{}
	if _, err := parseGroupMap(t, m); err == nil {
		t.Fatal("ignored explicit field")
	}
}
func TestGroupExampleAndDesignParse(t *testing.T) {
	data, err := os.ReadFile("../../docs/design/HTTPS-DOMAIN-GROUPS.md")
	if err != nil {
		t.Fatal(err)
	}
	jsonBlock := strings.Split(strings.Split(string(data), "```json\n")[1], "```")[0]
	if _, err := parseConfig([]byte(jsonBlock), "."); err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob("../../examples/config*.example.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseConfig(data, "."); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
}

func TestGroupCLIValidatesUnselectedGroups(t *testing.T) {
	m := groupConfigData(1, 9)
	data, _ := json.Marshal(m)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	code, err := runCLI(context.Background(), []string{"probe", "--config", path, "--group", "g0"}, io.Discard, io.Discard)
	if code != 1 || err == nil || !strings.Contains(err.Error(), "g1") {
		t.Fatal("filter bypassed full validation", code, err)
	}
	for _, key := range []string{"SchemaVersion", "Groups", "DOMAIN"} {
		m := groupConfigData(1)
		m[key] = 1
		if _, err := parseGroupMap(t, m); err == nil {
			t.Fatalf("accepted alias %s", key)
		}
	}
}
