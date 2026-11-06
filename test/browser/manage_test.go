//go:build browser

package browser

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

func postJSON(t *testing.T, path string, body any, out any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", baseURL+path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+readToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("%s: %s", path, resp.Status)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
}

// A saved ask rule, scanned over the window, gives decisions; "Always deny"
// adds a rule to the active policy, and a delete asks first.
func TestManageDecisionBecomesARule(t *testing.T) {
	var pol struct {
		ID string `json:"id"`
	}
	postJSON(t, "/api/v1/policies", map[string]any{
		"version": 2, "name": "journey",
		"defaults": map[string]string{"egress": "allow", "ingress": "allow", "intra_zone": "allow", "dns": "allow"},
		"rules": []map[string]any{{"name": "ask example", "action": "ask", "direction": "out",
			"remote": map[string]any{"type": "domain", "values": []string{"example.com"}}}},
	}, &pol)
	postJSON(t, "/api/v1/policies/"+pol.ID+"/activate", nil, nil)

	s := open(t, window(), "")
	s.run(chromedp.Evaluate(`document.querySelector('[data-tab="findings"]')?.click()`, nil))
	s.waitFor("Manage under Findings", `!!document.querySelector('#subtabs [data-tab="manage"]')`)
	s.run(chromedp.Click(`#subtabs [data-tab="manage"]`, chromedp.ByQuery))
	s.waitFor("the saved policy", `document.querySelector("#manage-body")?.textContent.includes("journey")`)
	s.run(chromedp.Click(`#manage-scan`, chromedp.ByQuery))
	s.waitFor("a decision", `!!document.querySelector('#manage-body [data-decision$=":rule:deny"]')`)
	s.clickNow(`#manage-body [data-decision$=":rule:deny"]`)
	s.waitFor("the policy to have two rules", `[...document.querySelectorAll("#manage-body tr")].some((r) => r.textContent.includes("journey") && r.children[3]?.textContent === "2")`)

	// The dialog is dismissed by the test harness, so nothing is deleted.
	before := s.dialogs.Load()
	s.clickNow(`#manage-body [data-policy-delete]`)
	for i := 0; s.dialogs.Load() == before; i++ {
		if i > 50 {
			t.Fatal("deleting a policy didn't ask first")
		}
		time.Sleep(100 * time.Millisecond)
	}
	s.waitFor("the policy to stay", `document.querySelector("#manage-body")?.textContent.includes("journey")`)
}
