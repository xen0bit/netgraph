package policy

import "testing"

func TestAuditFindsRedundantAndContradictory(t *testing.T) {
	p := &Policy{
		Version: 2,
		Zones:   []Zone{{Name: "lan", Devices: []string{"any"}}},
		RulesV2: []RuleV2{
			{Name: "allow web", Action: ActionAllow, Direction: "out", Local: Selector{Type: "zone", Values: []string{"lan"}}, Remote: Selector{Type: "domain", Values: []string{"example.com"}}, Ports: []string{"443"}},
			{Name: "allow web again", Action: ActionAllow, Direction: "out", Local: Selector{Type: "zone", Values: []string{"lan"}}, Remote: Selector{Type: "domain", Values: []string{"www.example.com"}}, Ports: []string{"443"}},
			{Name: "deny web", Action: ActionDeny, Direction: "out", Local: Selector{Type: "zone", Values: []string{"lan"}}, Remote: Selector{Type: "domain", Values: []string{"example.com"}}, Ports: []string{"443"}},
			{Name: "bad profile", Action: ActionAllow, Profile: "nope", Local: Selector{Type: "any"}, Remote: Selector{Type: "any"}},
		},
	}
	rep := Audit(p, []string{"home"}, nil)
	if rep.Summary["redundant"] == 0 && rep.Summary["shadowed"] == 0 {
		t.Fatalf("no redundancy finding: %+v", rep)
	}
	if rep.Summary["contradictory"] == 0 {
		t.Fatalf("no contradictory finding: %+v", rep)
	}
	if rep.Summary["invalid"] == 0 {
		t.Fatalf("no invalid profile finding: %+v", rep)
	}
	// Deterministic ordering.
	again := Audit(p, []string{"home"}, nil)
	if len(again.Findings) != len(rep.Findings) {
		t.Fatalf("audit is not deterministic")
	}
	for i := range rep.Findings {
		if rep.Findings[i] != again.Findings[i] {
			t.Fatalf("audit changed at %d", i)
		}
	}
}

func TestAuditDoesNotFlagIndependentRules(t *testing.T) {
	p := &Policy{
		Version: 2,
		Zones:   []Zone{{Name: "lan", Devices: []string{"any"}}},
		RulesV2: []RuleV2{
			{Name: "a", Action: ActionAllow, Local: Selector{Type: "zone", Values: []string{"lan"}}, Remote: Selector{Type: "domain", Values: []string{"a.example"}}},
			{Name: "b", Action: ActionAllow, Local: Selector{Type: "zone", Values: []string{"lan"}}, Remote: Selector{Type: "domain", Values: []string{"b.example"}}},
		},
	}
	rep := Audit(p, nil, nil)
	if rep.Summary["redundant"] != 0 || rep.Summary["shadowed"] != 0 || rep.Summary["contradictory"] != 0 {
		t.Fatalf("independent rules flagged: %+v", rep)
	}
}
