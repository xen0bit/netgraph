package store

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/xen0bit/netgraph/internal/model"
)

// Ask answers a question from recorded evidence. This is the deterministic
// intent mode: it never invents a fact, and every sentence carries a
// citation. A local model can rephrase the result later, but cannot add
// claims.
func (s *Store) Ask(ctx context.Context, question string, f model.Filter) (*model.Answer, error) {
	out := &model.Answer{Question: question, Confidence: "low"}
	words := questionWords(question)
	if len(words) == 0 {
		out.Answer = "Ask a question about a device, a name, the window or an anomaly."
		return out, nil
	}
	has := func(names ...string) bool {
		for _, w := range words {
			if slices.Contains(names, w) {
				return true
			}
		}
		return false
	}
	from, to := s.window(f)
	out.Plan = append(out.Plan, model.ToolCall{Tool: "window", Args: map[string]string{"from": time.UnixMilli(from).UTC().Format(time.RFC3339), "to": time.UnixMilli(to).UTC().Format(time.RFC3339)}})
	if has("yesterday", "today", "tonight", "morning", "afternoon", "evening", "ago", "last", "week", "month") {
		out.Gaps = append(out.Gaps, "times in the question are not interpreted; this answers the selected window")
	}
	var err error
	switch {
	case has("changed", "change", "changes", "difference", "differences", "diff", "different"):
		err = s.askDiff(ctx, out, from, to)
	case has("anomaly", "anomalies", "anomalous", "alert", "alerts", "problem", "problems"):
		err = s.askAnomalies(ctx, out, f)
	default:
		var found bool
		if found, err = s.askEntity(ctx, out, words, f); err == nil && !found {
			if has("happened", "happening", "moment", "then") {
				out.Gaps = nil
				err = s.askMoment(ctx, out, f, to)
			} else {
				out.Answer = "I could not find an entity matching that question."
				out.Gaps = append(out.Gaps, "no matching device, address, name or network in the retained data")
			}
		}
	}
	if err != nil {
		return nil, err
	}
	// The promise of this mode: a sentence without a record behind it is
	// dropped, and the answer's evidence is exactly what its claims cite.
	kept := out.Claims[:0]
	seen := map[string]bool{}
	for _, c := range out.Claims {
		if len(c.Evidence) == 0 {
			continue
		}
		kept = append(kept, c)
		for _, e := range c.Evidence {
			if k := e.Kind + ":" + e.ID; !seen[k] {
				seen[k] = true
				out.Evidence = append(out.Evidence, e)
			}
		}
	}
	out.Claims = kept
	return out, nil
}

func (s *Store) askDiff(ctx context.Context, out *model.Answer, from, to int64) error {
	lb := max(min(to-from, time.Hour.Milliseconds()), 5*time.Minute.Milliseconds())
	fa := model.Filter{From: time.UnixMilli(from), To: time.UnixMilli(from + lb)}
	fb := model.Filter{From: time.UnixMilli(to - lb), To: time.UnixMilli(to)}
	out.Plan = append(out.Plan, model.ToolCall{Tool: "diff", Args: map[string]string{"a": fa.To.UTC().Format(time.RFC3339), "b": fb.To.UTC().Format(time.RFC3339)}})
	d, err := s.Diff(ctx, fa, fb, "")
	if err != nil {
		return err
	}
	out.Confidence = "high"
	out.Answer = fmt.Sprintf("%d things were added, %d removed and %d changed between the two moments.", len(d.Added), len(d.Removed), len(d.Changed))
	for _, x := range firstN(d.Added, 5) {
		out.Claims = append(out.Claims, model.Claim{Text: fmt.Sprintf("Added %s %s.", x.Kind, firstNonEmpty(x.Label, x.Key)), Evidence: x.Evidence})
	}
	for _, x := range firstN(d.Removed, 5) {
		out.Claims = append(out.Claims, model.Claim{Text: fmt.Sprintf("Removed %s %s.", x.Kind, firstNonEmpty(x.Label, x.Key)), Evidence: x.Evidence})
	}
	out.Gaps = append(out.Gaps, d.Gaps...)
	return nil
}

func (s *Store) askAnomalies(ctx context.Context, out *model.Answer, f model.Filter) error {
	rep, err := s.Anomalies(ctx, f)
	if err != nil {
		return err
	}
	out.Plan = append(out.Plan, model.ToolCall{Tool: "anomalies"})
	out.Answer = fmt.Sprintf("I found %d anomalies in the window.", len(rep.Anomalies))
	if rep.Learning {
		out.Gaps = append(out.Gaps, "the network is still learning its history")
	}
	for _, a := range firstN(rep.Anomalies, 8) {
		out.Claims = append(out.Claims, model.Claim{Text: fmt.Sprintf("[%s] %s", a.Severity, a.Summary), Evidence: anomalyEvidence(a)})
	}
	out.Confidence = "high"
	return nil
}

func (s *Store) askMoment(ctx context.Context, out *model.Answer, f model.Filter, to int64) error {
	ff := f
	ff.From = time.UnixMilli(to).Add(-5 * time.Minute)
	out.Plan = append(out.Plan, model.ToolCall{Tool: "frame", Args: map[string]string{"at": time.UnixMilli(to).UTC().Format(time.RFC3339)}})
	fr, err := s.frame(ctx, ff, false)
	if err != nil {
		return err
	}
	out.Answer = fmt.Sprintf("Around %s: %d devices, %d connections, %s sent and %s received in the preceding %s.", time.UnixMilli(to).UTC().Format(time.RFC3339), fr.Summary.Devices, fr.Summary.Flows, model.FormatBytes(fr.Summary.BytesOut), model.FormatBytes(fr.Summary.BytesIn), time.Duration(fr.LookbackMS)*time.Millisecond)
	out.Claims = append(out.Claims, model.Claim{Text: out.Answer, Evidence: []model.EvidenceRef{{Kind: "frame", ID: fmt.Sprint(to), TS: to, Text: "frame around the moment"}}})
	for _, d := range firstN(fr.Devices, 5) {
		out.Claims = append(out.Claims, model.Claim{Text: fmt.Sprintf("%s was active.", d.Label), Evidence: []model.EvidenceRef{{Kind: "entity", ID: d.ID, TS: d.LastSeen, Text: d.Label}}})
	}
	out.Confidence = "high"
	return nil
}

// askEntity finds the entity the question names and tells its story. It
// reports false when the question names nothing that was recorded.
func (s *Store) askEntity(ctx context.Context, out *model.Answer, words []string, f model.Filter) (bool, error) {
	terms := searchTerms(words)
	if len(terms) == 0 {
		return false, nil
	}
	out.Plan = append(out.Plan, model.ToolCall{Tool: "search", Args: map[string]string{"q": strings.Join(terms, " ")}})
	var results []model.SearchResult
	for _, q := range append([]string{strings.Join(terms, " ")}, terms...) {
		var err error
		if results, err = s.Search(ctx, q, 5); err != nil {
			return false, err
		}
		if len(results) > 0 {
			break
		}
	}
	if len(results) == 0 {
		return false, nil
	}
	r := results[0]
	out.Plan = append(out.Plan, model.ToolCall{Tool: "story", Args: map[string]string{"entity": r.ID}})
	story, err := s.Story(ctx, r.ID, f)
	if err != nil {
		return false, err
	}
	out.Answer = fmt.Sprintf("%s (%s) has %d recorded intervals in this window.", story.Label, story.Entity, len(story.Segments))
	out.Claims = append(out.Claims, model.Claim{Text: out.Answer, Evidence: []model.EvidenceRef{{Kind: "entity", ID: story.Entity, Text: story.Label}}})
	for _, seg := range firstN(story.Segments, 6) {
		out.Claims = append(out.Claims, model.Claim{
			Text:     fmt.Sprintf("%s: %s", seg.Kind, seg.Label),
			Evidence: seg.Evidence,
		})
	}
	out.Gaps = append(out.Gaps, story.Gaps...)
	if len(results) > 1 {
		out.Gaps = append(out.Gaps, fmt.Sprintf("%d other entities also match; this is the closest", len(results)-1))
	}
	if len(story.Segments) > 0 {
		out.Confidence = "high"
		if len(results) > 1 {
			out.Confidence = "medium"
		}
	}
	out.Followups = []string{"show me the timeline", "what changed around this", "any anomalies?"}
	return true, nil
}

// questionWords splits a question into lower-case words. An address, MAC or
// hostname stays one word; sentence punctuation around it does not stick.
func questionWords(q string) []string {
	var out []string
	for _, w := range strings.FieldsFunc(strings.ToLower(q), func(r rune) bool {
		return r != '-' && r != ':' && r != '.' && r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		if w = strings.Trim(w, "-:._"); w != "" {
			out = append(out, w)
		}
	}
	return out
}

// searchTerms is what is left of a question to search for.
func searchTerms(words []string) []string {
	var out []string
	for _, w := range words {
		if len(w) > 1 && !askStopWords[w] {
			out = append(out, w)
		}
	}
	return firstN(out, 4)
}

var askStopWords = func() map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(`a about after ago am an and any are around at be been before by
		day did do does doing done for from give happen happened happening has have how i in is it
		last me moment month morning my of on or show so tell that the then there this to today
		tonight us was week were what when where which who why with yesterday afternoon evening`) {
		m[w] = true
	}
	return m
}()

func firstN[T any](in []T, n int) []T {
	if len(in) > n {
		return in[:n]
	}
	return in
}

func anomalyEvidence(a model.Anomaly) []model.EvidenceRef {
	out := []model.EvidenceRef{{Kind: "anomaly", ID: a.Kind + ":" + fmt.Sprint(a.TS), TS: a.TS, Text: a.Summary}}
	for k, v := range a.Evidence {
		out = append(out, model.EvidenceRef{Kind: "anomaly", ID: a.Kind + ":" + fmt.Sprint(a.TS) + ":" + k, TS: a.TS, Text: v})
	}
	slices.SortFunc(out, func(x, y model.EvidenceRef) int { return strings.Compare(x.ID, y.ID) })
	return out
}
