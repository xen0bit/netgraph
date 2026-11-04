package store

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/xen0bit/netgraph/internal/classify"
	"github.com/xen0bit/netgraph/internal/model"
)

// Ask answers a question from recorded evidence, reading times in the server's
// timezone. See AskIn.
func (s *Store) Ask(ctx context.Context, question string, f model.Filter) (*model.Answer, error) {
	return s.AskIn(ctx, question, f, time.Local)
}

// AskIn answers a question from recorded evidence. This is the deterministic
// intent mode: it never invents a fact, and every sentence carries a
// citation. loc is the reader's timezone, for "yesterday" and "3pm". A time in the
// question replaces the window it was asked over.
func (s *Store) AskIn(ctx context.Context, question string, f model.Filter, loc *time.Location) (*model.Answer, error) {
	out := &model.Answer{Question: question, Confidence: "low"}
	if len(questionWords(question)) == 0 {
		out.Answer = "Ask a question about a device, a name, the window or an anomaly."
		return out, nil
	}
	parts := splitCompound(question)
	var sentences []string
	confidence := ""
	for _, part := range parts {
		one := &model.Answer{Question: part, Confidence: "low"}
		if err := s.askOne(ctx, one, part, f, loc); err != nil {
			return nil, err
		}
		sentences = append(sentences, one.Answer)
		out.Plan = append(out.Plan, one.Plan...)
		out.Claims = append(out.Claims, one.Claims...)
		for _, g := range one.Gaps {
			if !slices.Contains(out.Gaps, g) {
				out.Gaps = append(out.Gaps, g)
			}
		}
		out.Followups = append(out.Followups, one.Followups...)
		out.FromMS, out.ToMS, out.Focus = one.FromMS, one.ToMS, one.Focus
		// As sure as its least sure part.
		if confidence == "" || askRank[one.Confidence] < askRank[confidence] {
			confidence = one.Confidence
		}
	}
	if len(parts) > 1 {
		out.Focus = ""
	}
	out.Answer, out.Confidence = strings.Join(sentences, " "), confidence
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

var askRank = map[string]int{"low": 0, "medium": 1, "high": 2}

func (s *Store) askOne(ctx context.Context, out *model.Answer, question string, f model.Filter, loc *time.Location) error {
	words := questionWords(question)
	has := func(names ...string) bool {
		for _, w := range words {
			if slices.Contains(names, w) {
				return true
			}
		}
		return false
	}
	var when *askWindow
	when, words = parseAskTime(words, s.cfg.Now(), loc)
	if when != nil {
		f.From, f.To = when.from, when.to
	}
	from, to := s.window(f)
	out.FromMS, out.ToMS = from, to
	args := map[string]string{"from": time.UnixMilli(from).UTC().Format(time.RFC3339), "to": time.UnixMilli(to).UTC().Format(time.RFC3339)}
	if when != nil {
		args["asked"] = when.label
	}
	out.Plan = append(out.Plan, model.ToolCall{Tool: "window", Args: args})
	if when == nil && hasAny(words, "yesterday", "tonight", "morning", "afternoon", "evening", "ago", "last", "week", "month", "next") {
		out.Gaps = append(out.Gaps, "a time in the question wasn't understood; this answers the selected window")
	}
	if to <= from {
		out.Answer = "That time hasn't happened yet."
		return nil
	}
	var err error
	switch {
	case hasAny(words, "slow", "slower", "lag", "laggy", "latency", "buffering") && !s.entityNamed(ctx, words):
		err = s.askSlow(ctx, out, f)
	case has("changed", "change", "changes", "difference", "differences", "diff", "different"):
		err = s.askDiff(ctx, out, from, to)
	case has("anomaly", "anomalies", "anomalous", "alert", "alerts", "problem", "problems", "findings", "finding", "suspicious", "wrong", "worry"):
		err = s.askAnomalies(ctx, out, f)
	case isRanking(words):
		err = s.askRanking(ctx, out, words, f)
	case hasAny(words, "home", "online", "here", "connected", "around") && hasAny(words, "who", "whos", "what", "which", "anyone", "anybody", "everyone"):
		err = s.askWhoHere(ctx, out, f, to)
	case hasAny(words, "new") && hasAny(words, "device", "devices", "joined", "appeared"):
		err = s.askNewDevices(ctx, out, f, from)
	default:
		var found bool
		if found, err = s.askProfile(ctx, out, words, f); err == nil && !found {
			found, err = s.askEntity(ctx, out, words, f)
		}
		if err == nil && !found {
			if has("happened", "happening", "moment", "then") {
				out.Gaps = nil
				err = s.askMoment(ctx, out, f, to)
			} else {
				out.Answer = "I could not find an entity matching that question."
				out.Gaps = append(out.Gaps, "no matching device, address, name or network in the retained data")
			}
		}
	}
	return err
}

func hasAny(words []string, names ...string) bool {
	return slices.ContainsFunc(words, func(w string) bool { return slices.Contains(names, w) })
}

// splitCompound splits "who's home and any anomalies?" into its questions. Only on
// "and" or "also" between two things that are each a question of their own: "alice
// and bob's traffic" stays whole.
func splitCompound(q string) []string {
	var parts []string
	var cur []string
	for _, f := range strings.Fields(q) {
		if w := strings.ToLower(strings.Trim(f, ",.;")); w == "and" || w == "also" {
			parts = append(parts, strings.Join(cur, " "))
			cur = nil
			continue
		}
		cur = append(cur, f)
	}
	parts = append(parts, strings.Join(cur, " "))
	if len(parts) < 2 {
		return []string{q}
	}
	for _, p := range parts {
		if !standsAlone(questionWords(p)) {
			return []string{q}
		}
	}
	return parts
}

// standsAlone says whether words make a question by themselves, with no help from
// the rest of the sentence.
func standsAlone(w []string) bool {
	return isRanking(w) ||
		hasAny(w, "changed", "changes", "anomaly", "anomalies", "alerts", "problems", "findings", "suspicious") ||
		(hasAny(w, "home", "online", "here") && hasAny(w, "who", "whos", "what", "which", "anyone", "anybody")) ||
		(hasAny(w, "new") && hasAny(w, "device", "devices")) ||
		hasAny(w, "what", "who", "when", "why", "did")
}

// --- times --------------------------------------------------------------------

type askWindow struct {
	from, to time.Time
	label    string
}

var askWeekdays = map[string]time.Weekday{"sunday": time.Sunday, "monday": time.Monday, "tuesday": time.Tuesday, "wednesday": time.Wednesday, "thursday": time.Thursday, "friday": time.Friday, "saturday": time.Saturday}

var askUnits = map[string]time.Duration{"minute": time.Minute, "minutes": time.Minute, "mins": time.Minute, "min": time.Minute,
	"hour": time.Hour, "hours": time.Hour, "hr": time.Hour, "hrs": time.Hour, "day": 24 * time.Hour, "days": 24 * time.Hour, "week": 7 * 24 * time.Hour, "weeks": 7 * 24 * time.Hour}

// parseAskTime finds a time in the question, and returns the words without it. The
// last word of a window never passes now: nothing is known about the future.
func parseAskTime(words []string, now time.Time, loc *time.Location) (*askWindow, []string) {
	local := now.In(loc)
	day := func(back int) time.Time {
		return time.Date(local.Year(), local.Month(), local.Day()-back, 0, 0, 0, 0, loc)
	}
	drop := func(i, n int) []string { return slices.Concat(words[:i], words[i+n:]) }
	span := func(from, to time.Time, label string) *askWindow {
		if to.After(now) {
			to = now
		}
		return &askWindow{from, to, label}
	}
	for i, w := range words {
		next := ""
		if i+1 < len(words) {
			next = words[i+1]
		}
		prev := ""
		if i > 0 {
			prev = words[i-1]
		}
		var day0 time.Time
		var dayLabel string
		n := 1
		switch {
		case (w == "last" || w == "past") && next == "night":
			return span(day(1).Add(18*time.Hour), day(0).Add(6*time.Hour), "last night"), drop(i, 2)
		case w == "this" && next == "morning":
			return span(day(0).Add(6*time.Hour), day(0).Add(12*time.Hour), "this morning"), drop(i, 2)
		case w == "this" && next == "afternoon":
			return span(day(0).Add(12*time.Hour), day(0).Add(18*time.Hour), "this afternoon"), drop(i, 2)
		case (w == "this" && next == "evening") || w == "tonight":
			c := 1
			if w == "this" {
				c = 2
			}
			return span(day(0).Add(18*time.Hour), day(-1), "this evening"), drop(i, c)
		case (w == "last" || w == "past") && askUnits[next] != 0:
			return span(now.Add(-askUnits[next]), now, w+" "+next), drop(i, 2)
		case (w == "last" || w == "past") && i+2 < len(words) && askNumber(next) > 0 && askUnits[words[i+2]] != 0:
			d := time.Duration(askNumber(next)) * askUnits[words[i+2]]
			return span(now.Add(-d), now, fmt.Sprintf("%s %s %s", w, next, words[i+2])), drop(i, 3)
		case askNumber(w) > 0 && askUnits[next] != 0 && i+2 < len(words) && words[i+2] == "ago":
			at := now.Add(-time.Duration(askNumber(w)) * askUnits[next])
			return span(at.Add(-30*time.Minute), at.Add(30*time.Minute), fmt.Sprintf("%s %s ago", w, next)), drop(i, 3)
		case w == "yesterday":
			day0, dayLabel = day(1), w
		case w == "today":
			day0, dayLabel = day(0), w
		case askWeekdaysHas(w):
			back := (int(local.Weekday()) - int(askWeekdays[w]) + 7) % 7
			if back == 0 {
				back = 7
			}
			day0, dayLabel = day(back), w
			if prev == "on" || prev == "last" {
				i--
				n = 2
			}
		default:
			continue
		}
		rest := drop(i, n)
		// "yesterday at 3pm", or "at 3pm yesterday".
		if h, j, used, ok := askClock(rest); ok {
			at := day0.Add(time.Duration(h) * time.Minute)
			return span(at.Add(-30*time.Minute), at.Add(30*time.Minute), dayLabel+" "+at.Format("15:04")), slices.Concat(rest[:j], rest[j+used:])
		}
		return span(day0, day0.AddDate(0, 0, 1), dayLabel), rest
	}
	// A clock time with no day: the last time it was that time.
	if h, j, used, ok := askClock(words); ok {
		at := day(0).Add(time.Duration(h) * time.Minute)
		if at.After(now) {
			at = day(1).Add(time.Duration(h) * time.Minute)
		}
		return span(at.Add(-30*time.Minute), at.Add(30*time.Minute), at.Format("15:04")), slices.Concat(words[:j], words[j+used:])
	}
	return nil, words
}

func askWeekdaysHas(w string) bool { _, ok := askWeekdays[w]; return ok }

var askNumberWords = map[string]int{"a": 1, "an": 1, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10, "twelve": 12}

// askNumber reads a small count; 0 when it isn't one.
func askNumber(w string) int {
	if n, ok := askNumberWords[w]; ok {
		return n
	}
	n := 0
	for _, r := range w {
		if r < '0' || r > '9' || n > 100000 {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// askClock finds "3pm", "3:30pm", "15:00" or "at 9", as minutes after midnight, with
// where it is. A bare number needs "at" before it: "port 22" isn't a time.
func askClock(words []string) (mins, at, used int, ok bool) {
	for i, w := range words {
		lead := 0
		if i > 0 && words[i-1] == "at" {
			lead = 1
		}
		if m, found := parseClock(w, lead == 1); found {
			return m, i - lead, 1 + lead, true
		}
		if i+1 < len(words) && (words[i+1] == "am" || words[i+1] == "pm") {
			if m, found := parseClock(w+words[i+1], false); found {
				return m, i - lead, 2 + lead, true
			}
		}
	}
	return 0, 0, 0, false
}

func parseClock(w string, bare bool) (int, bool) {
	suffix := ""
	switch {
	case strings.HasSuffix(w, "am"):
		suffix, w = "am", strings.TrimSuffix(w, "am")
	case strings.HasSuffix(w, "pm"):
		suffix, w = "pm", strings.TrimSuffix(w, "pm")
	}
	hs, ms, colon := strings.Cut(w, ":")
	if suffix == "" && !colon && !bare {
		return 0, false
	}
	if hs == "" || len(hs) > 2 || (colon && len(ms) != 2) {
		return 0, false
	}
	h, m := 0, 0
	for _, r := range hs {
		if r < '0' || r > '9' {
			return 0, false
		}
		h = h*10 + int(r-'0')
	}
	for _, r := range ms {
		if r < '0' || r > '9' {
			return 0, false
		}
		m = m*10 + int(r-'0')
	}
	if m > 59 || h > 23 {
		return 0, false
	}
	if suffix != "" {
		if h < 1 || h > 12 {
			return 0, false
		}
		h %= 12
		if suffix == "pm" {
			h += 12
		}
	}
	return h*60 + m, true
}

// --- rankings, profiles and presence ---------------------------------------------

func isRanking(w []string) bool {
	if hasAny(w, "biggest", "busiest", "largest", "top", "heaviest", "most") {
		return true
	}
	return hasAny(w, "who", "which", "what") && hasAny(w, "uploading", "uploaded", "downloading", "downloaded", "uploader", "downloader", "bandwidth")
}

func deviceEvidence(d model.Device, text string) []model.EvidenceRef {
	return []model.EvidenceRef{{Kind: "entity", ID: d.ID, TS: d.ActiveTo, Text: text}}
}

func (s *Store) askRanking(ctx context.Context, out *model.Answer, words []string, f model.Filter) error {
	if hasAny(words, "destination", "destinations", "site", "sites", "website", "websites", "domain", "domains", "talk", "talks", "visited") {
		out.Plan = append(out.Plan, model.ToolCall{Tool: "destinations"})
		dests, err := s.Destinations(ctx, f)
		if err != nil {
			return err
		}
		if len(dests) == 0 {
			out.Answer = "Nothing was reached in that time."
			return nil
		}
		out.Confidence = "high"
		out.Answer = fmt.Sprintf("%s was reached most: %s sent and %s received.", dests[0].Label, model.FormatBytes(dests[0].BytesOut), model.FormatBytes(dests[0].BytesIn))
		for _, d := range firstN(dests, 5) {
			id := model.EntityID(model.KindDomain, d.Key)
			if d.Kind != "" && d.Kind != model.KindDomain {
				id = model.EntityID(d.Kind, d.Key)
			}
			out.Claims = append(out.Claims, model.Claim{
				Text:     fmt.Sprintf("%s: %s sent, %s received, %d connections.", d.Label, model.FormatBytes(d.BytesOut), model.FormatBytes(d.BytesIn), d.Connections),
				Evidence: []model.EvidenceRef{{Kind: "entity", ID: id, TS: d.LastSeen, Text: d.Label}},
			})
		}
		return nil
	}
	out.Plan = append(out.Plan, model.ToolCall{Tool: "devices"})
	devs, err := s.Devices(ctx, f)
	if err != nil {
		return err
	}
	measure, verb := func(d model.Device) uint64 { return d.BytesIn + d.BytesOut }, "moved"
	switch {
	case hasAny(words, "upload", "uploader", "uploaders", "uploading", "uploaded", "sent", "sender", "sending"):
		measure, verb = func(d model.Device) uint64 { return d.BytesOut }, "sent"
	case hasAny(words, "download", "downloader", "downloaders", "downloading", "downloaded", "received", "receiving"):
		measure, verb = func(d model.Device) uint64 { return d.BytesIn }, "received"
	}
	slices.SortFunc(devs, func(a, b model.Device) int {
		return cmp.Or(cmp.Compare(measure(b), measure(a)), cmp.Compare(a.MAC, b.MAC))
	})
	if len(devs) == 0 || measure(devs[0]) == 0 {
		out.Answer = "No device " + verb + " anything in that time."
		return nil
	}
	out.Confidence = "high"
	out.Answer = fmt.Sprintf("%s %s the most: %s.", devs[0].Label, verb, model.FormatBytes(measure(devs[0])))
	out.Focus = devs[0].ID
	for _, d := range firstN(devs, 5) {
		if measure(d) == 0 {
			break
		}
		out.Claims = append(out.Claims, model.Claim{Text: fmt.Sprintf("%s %s %s.", d.Label, verb, model.FormatBytes(measure(d))), Evidence: deviceEvidence(d, d.Label)})
	}
	return nil
}

func (s *Store) askWhoHere(ctx context.Context, out *model.Answer, f model.Filter, to int64) error {
	// A window names when; "here" still means the last 10 minutes of it.
	g := f
	g.From = time.UnixMilli(to).Add(-homeActive)
	out.Plan = append(out.Plan, model.ToolCall{Tool: "devices", Args: map[string]string{"active_within": homeActive.String()}})
	devs, err := s.Devices(ctx, g)
	if err != nil {
		return err
	}
	out.Gaps = append(out.Gaps, "seen means it moved traffic in the 10 minutes before that time; a phone asleep on the network doesn't show")
	if len(devs) == 0 {
		out.Answer = "No device moved traffic in the 10 minutes before that time."
		out.Confidence = "medium"
		return nil
	}
	out.Confidence = "high"
	owners := []string{}
	for _, d := range devs {
		if d.Owner != "" && !slices.Contains(owners, d.Owner) {
			owners = append(owners, d.Owner)
		}
	}
	slices.Sort(owners)
	out.Answer = fmt.Sprintf("%d %s seen.", len(devs), plural(len(devs), "device was", "devices were"))
	if len(owners) > 0 {
		out.Answer = strings.Join(owners, ", ") + plural(len(owners), " has", " have") + " a device here. " + out.Answer
	}
	for _, d := range firstN(devs, 12) {
		out.Claims = append(out.Claims, model.Claim{Text: fmt.Sprintf("%s was active.", d.Label), Evidence: deviceEvidence(d, d.Label)})
	}
	return nil
}

func (s *Store) askNewDevices(ctx context.Context, out *model.Answer, f model.Filter, from int64) error {
	out.Plan = append(out.Plan, model.ToolCall{Tool: "devices", Args: map[string]string{"first_seen_after": time.UnixMilli(from).UTC().Format(time.RFC3339)}})
	devs, err := s.Devices(ctx, f)
	if err != nil {
		return err
	}
	devs = slices.DeleteFunc(devs, func(d model.Device) bool { return d.FirstSeen < from })
	out.Confidence = "high"
	if len(devs) == 0 {
		out.Answer = "No new device appeared in that time."
		return nil
	}
	out.Answer = fmt.Sprintf("%d new %s appeared.", len(devs), plural(len(devs), "device", "devices"))
	for _, d := range firstN(devs, 10) {
		out.Claims = append(out.Claims, model.Claim{Text: fmt.Sprintf("%s was first seen %s.", d.Label, time.UnixMilli(d.FirstSeen).UTC().Format(time.RFC3339)), Evidence: deviceEvidence(d, d.Label)})
	}
	return nil
}

// askSlow says what netgraph can and can't say: it doesn't measure latency yet, so
// it can only show who's using the connection.
func (s *Store) askSlow(ctx context.Context, out *model.Answer, f model.Filter) error {
	out.Gaps = append(out.Gaps, "netgraph doesn't measure latency or loss yet, so it can't say whether the connection itself is slow")
	devs, err := s.Devices(ctx, f)
	if err != nil {
		return err
	}
	out.Plan = append(out.Plan, model.ToolCall{Tool: "devices"})
	slices.SortFunc(devs, func(a, b model.Device) int {
		return cmp.Or(cmp.Compare(b.BytesIn+b.BytesOut, a.BytesIn+a.BytesOut), cmp.Compare(a.MAC, b.MAC))
	})
	if len(devs) == 0 || devs[0].BytesIn+devs[0].BytesOut == 0 {
		out.Answer = "I can't tell why, and no device moved much in that time."
		return nil
	}
	out.Confidence = "medium"
	out.Answer = fmt.Sprintf("I can't measure speed yet, but %s was using the most: %s.", devs[0].Label, model.FormatBytes(devs[0].BytesIn+devs[0].BytesOut))
	out.Focus = devs[0].ID
	for _, d := range firstN(devs, 3) {
		out.Claims = append(out.Claims, model.Claim{Text: fmt.Sprintf("%s moved %s.", d.Label, model.FormatBytes(d.BytesIn+d.BytesOut)), Evidence: deviceEvidence(d, d.Label)})
	}
	return nil
}

var askTypeWords = map[string]string{
	"printer": classify.Printer, "printers": classify.Printer, "phone": classify.Phone, "phones": classify.Phone, "tablet": classify.Tablet, "tablets": classify.Tablet,
	"computer": classify.Computer, "computers": classify.Computer, "laptop": classify.Computer, "laptops": classify.Computer, "pc": classify.Computer,
	"tv": classify.TV, "tvs": classify.TV, "television": classify.TV, "chromecast": classify.TV, "speaker": classify.Speaker, "speakers": classify.Speaker,
	"camera": classify.Camera, "cameras": classify.Camera, "nas": classify.NAS, "server": classify.Server, "servers": classify.Server,
	"console": classify.Game, "consoles": classify.Game, "playstation": classify.Game, "xbox": classify.Game, "router": classify.Router, "switch": classify.Switch,
}

// entityNamed says whether the question names something on record, by what's left
// after the common words. A name beats the word "slow" in it.
func (s *Store) entityNamed(ctx context.Context, words []string) bool {
	terms := slices.DeleteFunc(searchTerms(words), func(t string) bool {
		return hasAny([]string{t}, "slow", "slower", "lag", "laggy", "latency", "buffering", "internet", "wifi", "network", "connection")
	})
	for _, t := range terms {
		if r, err := s.Search(ctx, t, 1); err == nil && len(r) > 0 {
			return true
		}
	}
	return false
}

// askProfile answers about what a device is or whose it is: "the printer",
// "the cameras", "alice's devices". found is false if the question names neither.
func (s *Store) askProfile(ctx context.Context, out *model.Answer, words []string, f model.Filter) (bool, error) {
	facts, err := s.deviceFacts(ctx)
	if err != nil {
		return false, err
	}
	owners := map[string]string{}
	groups := map[string]string{}
	for _, d := range facts {
		if d.owner != "" {
			owners[strings.ToLower(d.owner)] = d.owner
		}
		for _, g := range d.groups {
			groups[strings.ToLower(g)] = g
		}
	}
	filter, what := "", ""
	for _, w := range words {
		bare := strings.TrimSuffix(w, "s")
		switch {
		case owners[w] != "":
			filter, what = "owner:"+w, owners[w]+"'s devices"
		case owners[bare] != "":
			filter, what = "owner:"+bare, owners[bare]+"'s devices"
		case groups[w] != "":
			filter, what = "group:"+w, "the "+groups[w]+" group"
		case askTypeWords[w] != "":
			filter, what = "type:"+askTypeWords[w], "the "+w
		default:
			continue
		}
		break
	}
	if filter == "" {
		return false, nil
	}
	// Nothing of that kind: it may still be something's name.
	ids, _, err := s.deviceIDsByProfile(ctx, filter)
	if err != nil {
		return false, err
	}
	if len(ids) == 0 {
		return false, nil
	}
	g := f
	g.Device = filter
	out.Plan = append(out.Plan, model.ToolCall{Tool: "devices", Args: map[string]string{"device": filter}})
	devs, err := s.Devices(ctx, g)
	if err != nil {
		return false, err
	}
	if len(devs) == 0 {
		out.Confidence = "medium"
		out.Answer = fmt.Sprintf("%s did nothing recorded in that time.", what)
		out.Claims = append(out.Claims, model.Claim{Text: out.Answer, Evidence: []model.EvidenceRef{{Kind: "query", ID: filter, Text: "no activity"}}})
		return true, nil
	}
	if len(devs) == 1 {
		return s.askStory(ctx, out, devs[0].ID, f, 0)
	}
	out.Confidence = "high"
	out.Answer = fmt.Sprintf("%s: %d were active.", what, len(devs))
	for _, d := range firstN(devs, 10) {
		out.Claims = append(out.Claims, model.Claim{
			Text:     fmt.Sprintf("%s: sent %s, received %s, %d connections.", d.Label, model.FormatBytes(d.BytesOut), model.FormatBytes(d.BytesIn), d.Flows),
			Evidence: deviceEvidence(d, d.Label),
		})
	}
	return true, nil
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
	return s.askStory(ctx, out, results[0].ID, f, len(results)-1)
}

// askStory tells an entity's recorded story. others says how many more entities the
// question could have meant.
func (s *Store) askStory(ctx context.Context, out *model.Answer, id string, f model.Filter, others int) (bool, error) {
	out.Plan = append(out.Plan, model.ToolCall{Tool: "story", Args: map[string]string{"entity": id}})
	story, err := s.Story(ctx, id, f)
	if err != nil {
		return false, err
	}
	if strings.HasPrefix(id, model.KindDevice+":") {
		out.Focus = id
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
	if others > 0 {
		out.Gaps = append(out.Gaps, fmt.Sprintf("%d other entities also match; this is the closest", others))
	}
	if len(story.Segments) > 0 {
		out.Confidence = "high"
		if others > 0 {
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
		tonight us was week were what when where which who why with yesterday afternoon evening
		night past hour hours minute minutes days weeks whos doing`) {
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
