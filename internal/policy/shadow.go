package policy

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/infamousjoeg/totem/internal/presence"
)

// Risk classes, in the order a human should read them: the irreversible and
// money lines are what they are actually checking.
const (
	riskMoney        = "money"
	riskIrreversible = "irreversible"
	riskWrite        = "write"
	riskRead         = "read"
)

var riskOrder = map[string]int{riskMoney: 0, riskIrreversible: 1, riskWrite: 2, riskRead: 3}

// propose is the `agents propose` algorithm.
//
//  1. Keep only COVERED observations. An uncovered request was parked and
//     either approved by a human or not; either way the shadow scope did not
//     sanction it, so a proposal built "from what the agent did" must not
//     quietly include it. It is counted and shown, never granted.
//  2. Intersect each axis with the sanctioned scope, so Proposed.Within(
//     Sanctioned) holds by construction: profiles and scopes actually used,
//     capabilities actually exercised, Claude only if used, the spend cap no
//     higher than sanctioned, money ceilings at the observed maxima rounded
//     up to whole dollars and never above sanctioned, the step-up threshold
//     at the floor.
//  3. Render three layers. Can: one line per relying party per risk, worst
//     risk first. Cannot: what the sanctioned scope had that the proposal
//     drops, plus the floors no grant lifts, in the same shape and order so
//     the eye reads both columns the same way. Reduction: the counts, as a
//     shrink.
func propose(agent string, sanctioned presence.Scope, obs []Observation, now time.Time) Proposal {
	sanctioned = sanctioned.Normalize()
	p := Proposal{Agent: agent, Sanctioned: sanctioned, Observed: len(obs), Until: now.Add(presence.DefaultGrantDuration)}

	used := presence.Scope{}
	var maxTx float64
	daily := map[time.Time]float64{}
	var claudeDaily = map[time.Time]float64{}
	for _, o := range obs {
		if !o.Covered {
			p.Uncovered++
			continue
		}
		switch o.Tool {
		case partyAWS:
			used.AWSProfiles = append(used.AWSProfiles, o.Target)
		case partyGitHub, partyGit:
			used.GitHubScopes = append(used.GitHubScopes, o.Target)
		case partyClaude:
			used.ClaudeProxy = true
			if o.AmountUSD > 0 {
				claudeDaily[day(o.At)] += o.AmountUSD
			}
			continue
		default:
			used.Capabilities = append(used.Capabilities, capability(o.Tool, o.Target))
		}
		if o.AmountUSD > 0 {
			maxTx = math.Max(maxTx, o.AmountUSD)
			daily[day(o.At)] += o.AmountUSD
		}
	}
	used = used.Normalize()

	proposed := presence.Scope{
		AWSProfiles:  intersect(used.AWSProfiles, sanctioned.AWSProfiles),
		GitHubScopes: intersect(used.GitHubScopes, sanctioned.GitHubScopes),
		Capabilities: intersect(used.Capabilities, sanctioned.Capabilities),
		ClaudeProxy:  used.ClaudeProxy && sanctioned.ClaudeProxy,
	}
	if proposed.ClaudeProxy {
		cap := sanctioned.SpendCapUSD
		if peak := maxOf(claudeDaily); peak > 0 {
			cap = math.Min(cap, dollars(peak))
		}
		proposed.SpendCapUSD = cap
	}
	if maxTx > 0 {
		proposed.Money = presence.Money{
			PerTransactionUSD: math.Min(sanctioned.Money.PerTransactionUSD, dollars(maxTx)),
			PerDayUSD:         math.Min(sanctioned.Money.PerDayUSD, dollars(maxOf(daily))),
			StepUpAboveUSD:    math.Min(sanctioned.Money.StepUpAboveUSD, presence.TrivialMoneyUSD),
		}
	}
	p.Proposed = proposed.Normalize()
	p.Can = canLines(p.Proposed)
	p.Cannot = cannotLines(sanctioned, p.Proposed)
	p.Reduction = reductionLines(sanctioned, p.Proposed, p.Uncovered)
	return p
}

func day(t time.Time) time.Time { return t.UTC().Truncate(24 * time.Hour) }

func maxOf(m map[time.Time]float64) float64 {
	var out float64
	for _, v := range m {
		out = math.Max(out, v)
	}
	return out
}

// dollars rounds an observed amount up to the next whole dollar, so the
// ceiling is legible and covers what was seen.
func dollars(v float64) float64 { return math.Ceil(v) }

func intersect(a, b []string) []string {
	var out []string
	for _, x := range a {
		if slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

func difference(a, b []string) []string {
	var out []string
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

// riskOf classifies one capability or scope string.
func riskOf(party, item string) string {
	s := strings.ToLower(item)
	action := s
	if i := strings.LastIndexAny(s, "#:"); i >= 0 {
		action = s[i+1:]
	}
	switch {
	case strings.Contains(s, "pay") || strings.Contains(s, "purchase") || strings.Contains(s, "spend"):
		return riskMoney
	case strings.Contains(action, "delete") || strings.Contains(action, "send") || strings.Contains(action, "post") ||
		strings.Contains(action, "unlock") || strings.Contains(action, "admin") || strings.Contains(action, "prod") ||
		strings.Contains(action, "force") || strings.Contains(action, "destroy"):
		return riskIrreversible
	case action == "read" || action == "get" || action == "list" || action == "status" || strings.HasSuffix(action, "read"):
		return riskRead
	}
	if party == partyAWS && (strings.Contains(s, "prod") || strings.Contains(s, "admin")) {
		return riskIrreversible
	}
	return riskWrite
}

// group buckets scope items by party and risk.
type bucket struct {
	party, risk string
	items       []string
}

func buckets(s presence.Scope) []bucket {
	m := map[[2]string][]string{}
	add := func(party, item string) {
		k := [2]string{party, riskOf(party, item)}
		m[k] = append(m[k], item)
	}
	for _, p := range s.AWSProfiles {
		add(partyAWS, p)
	}
	for _, g := range s.GitHubScopes {
		add("github", g)
	}
	for _, c := range s.Capabilities {
		party, rest, _ := strings.Cut(c, "/")
		if rest == "" {
			party = "other"
		}
		add(party, c)
	}
	out := make([]bucket, 0, len(m))
	for k, items := range m {
		sort.Strings(items)
		out = append(out, bucket{party: k[0], risk: k[1], items: items})
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].party != out[b].party {
			return out[a].party < out[b].party
		}
		return riskOrder[out[a].risk] < riskOrder[out[b].risk]
	})
	return out
}

func canLines(s presence.Scope) []Line {
	var out []Line
	if s.Money.PerTransactionUSD > 0 {
		out = append(out, Line{Party: "money", Risk: riskMoney, Text: fmt.Sprintf(
			"spend up to $%.0f per transaction and $%.0f per day; anything over $%.2f waits for you",
			s.Money.PerTransactionUSD, s.Money.PerDayUSD, math.Min(s.Money.StepUpAboveUSD, presence.TrivialMoneyUSD))})
	}
	if s.ClaudeProxy {
		out = append(out, Line{Party: partyClaude, Risk: riskWrite, Text: fmt.Sprintf("use Claude through the proxy, up to $%.0f", s.SpendCapUSD)})
	}
	for _, b := range buckets(s) {
		out = append(out, Line{Party: b.party, Risk: b.risk, Text: fmt.Sprintf("%s: %s (%s)", b.party, strings.Join(b.items, ", "), b.risk)})
	}
	return out
}

// cannotLines is the ceiling: everything sanctioned that the proposal drops,
// then the floors. It is rendered with the same weight as Can.
func cannotLines(sanctioned, proposed presence.Scope) []Line {
	var out []Line
	if sanctioned.Money.PerTransactionUSD > 0 && proposed.Money.PerTransactionUSD == 0 {
		out = append(out, Line{Party: "money", Risk: riskMoney, Text: "move money at all: no purchases, no payments, ever, without you"})
	} else if proposed.Money.PerTransactionUSD > 0 {
		out = append(out, Line{Party: "money", Risk: riskMoney, Text: fmt.Sprintf(
			"pay more than $%.2f without you present (hard floor, no grant lifts it), or more than $%.0f in one go or $%.0f in a day at all",
			presence.TrivialMoneyUSD, proposed.Money.PerTransactionUSD, proposed.Money.PerDayUSD)})
	} else {
		out = append(out, Line{Party: "money", Risk: riskMoney, Text: "move money at all"})
	}
	if sanctioned.ClaudeProxy && !proposed.ClaudeProxy {
		out = append(out, Line{Party: partyClaude, Risk: riskWrite, Text: "use Claude through the proxy"})
	} else if proposed.ClaudeProxy && proposed.SpendCapUSD < sanctioned.SpendCapUSD {
		out = append(out, Line{Party: partyClaude, Risk: riskWrite, Text: fmt.Sprintf("spend more than $%.0f on Claude (was allowed $%.0f)", proposed.SpendCapUSD, sanctioned.SpendCapUSD)})
	}
	dropped := presence.Scope{
		AWSProfiles:  difference(sanctioned.AWSProfiles, proposed.AWSProfiles),
		GitHubScopes: difference(sanctioned.GitHubScopes, proposed.GitHubScopes),
		Capabilities: difference(sanctioned.Capabilities, proposed.Capabilities),
	}
	for _, b := range buckets(dropped) {
		out = append(out, Line{Party: b.party, Risk: b.risk, Text: fmt.Sprintf("%s: %s (%s)", b.party, strings.Join(b.items, ", "), b.risk)})
	}
	out = append(out,
		Line{Party: "totem", Risk: riskIrreversible, Text: "widen itself: narrowing is instant, getting anything back needs your fingerprint"},
		Line{Party: "totem", Risk: riskIrreversible, Text: "turn off logging or your kill switch: nothing it does is ever out of scope to revoke"},
		Line{Party: "totem", Risk: riskIrreversible, Text: "reach anything not on this list: default deny"},
	)
	return out
}

func reductionLines(sanctioned, proposed presence.Scope, uncovered int) []Line {
	var out []Line
	count := func(party string, was, now []string) {
		if len(was) == 0 && len(now) == 0 {
			return
		}
		d := difference(was, now)
		text := fmt.Sprintf("%s: %d -> %d", party, len(was), len(now))
		if len(d) > 0 {
			text += " (drops " + strings.Join(d, ", ") + ")"
		}
		out = append(out, Line{Party: party, Risk: riskWrite, Text: text})
	}
	count(partyAWS, sanctioned.AWSProfiles, proposed.AWSProfiles)
	count("github", sanctioned.GitHubScopes, proposed.GitHubScopes)
	count("capabilities", sanctioned.Capabilities, proposed.Capabilities)
	if sanctioned.Money.PerTransactionUSD > 0 || proposed.Money.PerTransactionUSD > 0 {
		out = append(out, Line{Party: "money", Risk: riskMoney, Text: fmt.Sprintf("money: $%.0f/tx $%.0f/day -> $%.0f/tx $%.0f/day",
			sanctioned.Money.PerTransactionUSD, sanctioned.Money.PerDayUSD, proposed.Money.PerTransactionUSD, proposed.Money.PerDayUSD)})
	}
	if sanctioned.ClaudeProxy || proposed.ClaudeProxy {
		out = append(out, Line{Party: partyClaude, Risk: riskWrite, Text: fmt.Sprintf("claude: $%.0f -> $%.0f", sanctioned.SpendCapUSD, proposed.SpendCapUSD)})
	}
	if uncovered > 0 {
		out = append(out, Line{Party: "totem", Risk: riskIrreversible, Text: fmt.Sprintf("%d request(s) fell outside even the sanctioned scope; they were parked and are NOT in this proposal", uncovered)})
	}
	return out
}

// renderProposal writes the three layers. CAN and CANNOT share one heading
// style and CANNOT comes second but is never shorter, because the floors
// are always in it; a human skimming sees both blocks before any policy.
func renderProposal(p Proposal) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Grant for %s until %s (%d requests observed, %d outside scope)\n\n", p.Agent, p.Until.Format("2006-01-02"), p.Observed, p.Uncovered)
	b.WriteString("CAN\n")
	if len(p.Can) == 0 {
		b.WriteString("  nothing: no covered request was observed\n")
	}
	for _, l := range p.Can {
		fmt.Fprintf(&b, "  + %s\n", l.Text)
	}
	b.WriteString("\nCANNOT\n")
	for _, l := range p.Cannot {
		fmt.Fprintf(&b, "  - %s\n", l.Text)
	}
	b.WriteString("\nREDUCTION from what you sanctioned\n")
	if len(p.Reduction) == 0 {
		b.WriteString("  none\n")
	}
	for _, l := range p.Reduction {
		fmt.Fprintf(&b, "  %s\n", l.Text)
	}
	raw, _ := json.Marshal(scopeToJSON(p.Proposed))
	fmt.Fprintf(&b, "\nraw: %s\n", raw)
	return b.String()
}
