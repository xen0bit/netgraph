package store

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
)

// Ask answers a question from recorded evidence. This is the deterministic
// intent mode: it never invents a fact, and every sentence carries a
// citation. A local model can rephrase the result later, but cannot add
// claims.
func (s *Store) Ask(ctx context.Context, question string, f model.Filter) (*model.Answer, error) {
	q := strings.ToLower(strings.TrimSpace(question))
	out := &model.Answer{Question: question, Confidence: "low"}
	if q == "" {
		out.Answer = "Ask a question about a device, a name, the window or an anomaly."
		return out, nil
	}
	from, to := s.window(f)
	out.Plan = append(out.Plan, model.ToolCall{Tool: "window", Args: map[string]string{"from": time.UnixMilli(from).UTC().Format(time.RFC3339), "to": time.UnixMilli(to).UTC().Format(time.RFC3339)}})
	if strings.Contains(q, "changed") || strings.Contains(q, "difference") || strings.Contains(q, "diff") {
		lb := min(to-from, int64(time.Hour/time.Millisecond))
		if lb < 5*60_000 {
			lb = 5 * 60_000
		}
		fa := model.Filter{From: time.UnixMilli(from), To: time.UnixMilli(from + lb)}
		fb := model.Filter{From: time.UnixMilli(to - lb), To: time.UnixMilli(to)}
		out.Plan = append(out.Plan, model.ToolCall{Tool: "diff", Args: map[string]string{"a": fa.From.Format(time.RFC3339), "b": fb.To.Format(time.RFC3339)}})
		d, err := s.Diff(ctx, fa, fb, "")
		if err != nil {
			return nil, err
		}
		out.Confidence = "high"
		out.Answer = fmt.Sprintf("%d things were added, %d removed and %d changed between the two moments.", len(d.Added), len(d.Removed), len(d.Changed))
		for _, x := range firstN(d.Added, 5) {
			out.Claims = append(out.Claims, model.Claim{Text: fmt.Sprintf("Added %s %s.", x.Kind, x.Label), Evidence: x.Evidence})
		}
		for _, x := range firstN(d.Removed, 5) {
			out.Claims = append(out.Claims, model.Claim{Text: fmt.Sprintf("Removed %s %s.", x.Kind, x.Label), Evidence: x.Evidence})
		}
		return out, nil
	}
	if strings.Contains(q, "anomal") || strings.Contains(q, "alert") || strings.Contains(q, "problem") {
		rep, err := s.Anomalies(ctx, f)
		if err != nil {
			return nil, err
		}
		out.Plan = append(out.Plan, model.ToolCall{Tool: "anomalies"})
		out.Answer = fmt.Sprintf("I found %d anomalies in the window.", len(rep.Anomalies))
		if rep.Learning {
			out.Gaps = append(out.Gaps, "the network is still learning its history")
		}
		for _, a := range firstNAnomaly(rep.Anomalies, 8) {
			out.Claims = append(out.Claims, model.Claim{Text: fmt.Sprintf("[%s] %s", a.Severity, a.Summary), Evidence: anomalyEvidence(a)})
		}
		out.Confidence = "high"
		return out, nil
	}
	if strings.Contains(q, "happened") || strings.Contains(q, "moment") || strings.Contains(q, "then") {
		lb := int64(5 * time.Minute / time.Millisecond)
		ff := f
		ff.From = time.UnixMilli(to - lb)
		out.Plan = append(out.Plan, model.ToolCall{Tool: "frame", Args: map[string]string{"at": time.UnixMilli(to).UTC().Format(time.RFC3339)}})
		fr, err := s.Frame(ctx, ff)
		if err != nil {
			return nil, err
		}
		if fr.Summary != nil {
			out.Answer = fmt.Sprintf("Around %s: %d devices, %d connections, %s sent and %s received in the preceding %s.", time.UnixMilli(to).UTC().Format(time.RFC3339), fr.Summary.Devices, fr.Summary.Flows, model.FormatBytes(fr.Summary.BytesOut), model.FormatBytes(fr.Summary.BytesIn), time.Duration(fr.LookbackMS)*time.Millisecond)
			out.Claims = append(out.Claims, model.Claim{Text: out.Answer, Evidence: []model.EvidenceRef{{Kind: "frame", ID: fmt.Sprint(to), TS: to, Text: "frame around the moment"}}})
			for _, d := range firstN(fr.Devices, 5) {
				out.Claims = append(out.Claims, model.Claim{Text: fmt.Sprintf("%s was active.", d.Label), Evidence: []model.EvidenceRef{{Kind: "entity", ID: d.ID, TS: d.LastSeen, Text: d.Label}}})
			}
			out.Confidence = "high"
		}
		return out, nil
	}
	// Default: find the entity the question names, then tell its story.
	terms := searchTerms(q)
	out.Plan = append(out.Plan, model.ToolCall{Tool: "search", Args: map[string]string{"q": strings.Join(terms, " ")}})
	results, err := s.Search(ctx, strings.Join(terms, " "), 5)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 && len(terms) > 0 {
		results, _ = s.Search(ctx, terms[0], 5)
	}
	if len(results) == 0 {
		out.Answer = "I could not find an entity matching that question."
		out.Gaps = append(out.Gaps, "no matching device, address, name or network in the retained data")
		return out, nil
	}
	r := results[0]
	out.Plan = append(out.Plan, model.ToolCall{Tool: "story", Args: map[string]string{"entity": r.ID}})
	story, err := s.Story(ctx, r.ID, f)
	if err != nil {
		return nil, err
	}
	out.Answer = fmt.Sprintf("%s (%s) has %d recorded intervals in this window.", story.Label, story.Entity, len(story.Segments))
	out.Claims = append(out.Claims, model.Claim{Text: out.Answer, Evidence: []model.EvidenceRef{{Kind: "entity", ID: story.Entity, TS: from, Text: story.Label}}})
	for _, seg := range firstNSeg(story.Segments, 6) {
		out.Claims = append(out.Claims, model.Claim{
			Text:     fmt.Sprintf("%s: %s", seg.Kind, seg.Label),
			Evidence: seg.Evidence,
		})
	}
	if len(story.Gaps) > 0 {
		out.Gaps = append(out.Gaps, story.Gaps...)
	}
	out.Confidence = "high"
	out.Followups = []string{"show me the timeline", "what changed around this", "any anomalies?"}
	for _, c := range out.Claims {
		out.Evidence = append(out.Evidence, c.Evidence...)
	}
	return out, nil
}

func searchTerms(q string) []string {
	stop := map[string]bool{"what": true, "did": true, "do": true, "does": true, "the": true, "a": true, "an": true, "at": true, "on": true, "in": true, "to": true, "for": true, "with": true, "yesterday": true, "today": true, "last": true, "show": true, "me": true, "why": true, "how": true, "is": true, "was": true, "were": true}
	var out []string
	for _, w := range strings.FieldsFunc(q, func(r rune) bool {
		return !(r == '-' || r == ':' || r == '.' || r == '*' || r == '?' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z')
	}) {
		if len(w) > 1 && !stop[w] {
			out = append(out, w)
		}
	}
	if len(out) > 4 {
		out = out[:4]
	}
	return out
}

func firstN[T any](in []T, n int) []T {
	if len(in) > n {
		return in[:n]
	}
	return in
}

func firstNSeg(in []model.StorySegment, n int) []model.StorySegment { return firstN(in, n) }

func firstNAnomaly(in []model.Anomaly, n int) []model.Anomaly { return firstN(in, n) }

func anomalyEvidence(a model.Anomaly) []model.EvidenceRef {
	out := []model.EvidenceRef{{Kind: "anomaly", ID: a.Kind + ":" + fmt.Sprint(a.TS), TS: a.TS, Text: a.Summary}}
	for k, v := range a.Evidence {
		out = append(out, model.EvidenceRef{Kind: "anomaly", ID: a.Kind + ":" + fmt.Sprint(a.TS) + ":" + k, TS: a.TS, Text: v})
	}
	slices.SortFunc(out, func(x, y model.EvidenceRef) int { return strings.Compare(x.ID, y.ID) })
	return out
}
