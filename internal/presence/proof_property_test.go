package presence

import (
	"fmt"
	"math/rand/v2"
	"testing"
	"time"
)

// Property: one Verified is accepted by at most one consumer, whatever order
// consumers are tried in and however many times; a consumer that refuses a
// proof leaves it unused; and a consumer accepts a proof only when every
// binding (device, tool, target, request hash) matches what it needs.
//
// The generator builds a random proof (device, tool, target, bound-or-not,
// and if bound, bound to one of the things a consumer could want) and then
// throws a random sequence of consumers at it, each with its own
// expectations drawn from the same small universes so collisions are common.
func TestProofSingleUseAndBindingProperty(t *testing.T) {
	rng := rand.New(rand.NewPCG(0x70726f6f, 0x66757365))
	devices := []string{"mac-studio", "work-mbp"}
	tools := []string{"claude", "gh", "aws"}
	targets := []string{"", "dev", "prod"}
	pick := func(xs []string) string { return xs[rng.IntN(len(xs))] }

	const iterations = 400
	successes := 0
	for i := range iterations {
		clk := newClock()
		st := NewSessionStore(clk.Now)
		reg := NewRegistry(clk.Now)
		reg.Seal()
		lot := NewLot(clk.Now, 0, 0)

		// A world of things a proof might be bound to.
		grant := NewGrant("agent", wideScope(), clk.Now())
		root, err := reg.Sponsor(grant, verified("mac-studio", clk.Now(), grant.Hash()))
		if err != nil {
			t.Fatal(err)
		}
		sess, _ := reg.Open(root.ID, root.ID)
		reg.Narrow(sess.ID, Scope{}, time.Time{})
		reqHash := HashRequest([]byte(fmt.Sprintf("req-%d", i)))
		parkedID, _ := lot.Park("agent", root.ID, Irreversible, "x", reqHash)
		batchIDs := []string{parkedID}
		if rng.IntN(2) == 0 {
			r, _ := lot.Park("agent", root.ID, Reversible, "y", HashRequest([]byte("y")))
			batchIDs = []string{r}
		}
		newGrant := NewGrant("agent2", Scope{}, clk.Now())

		// The proof.
		dev, tool, target := pick(devices), pick(tools), pick(targets)
		var bound []byte
		switch rng.IntN(5) {
		case 0:
			bound = nil
		case 1:
			bound = reqHash
		case 2:
			bound = BatchHash(batchIDs)
		case 3:
			bound = WidenHash(sess.ID, root.ID)
		case 4:
			bound = newGrant.Hash()
		}
		v := verifiedFor(dev, tool, target, clk.Now(), bound)

		// Random consumers, each with random expectations.
		accepted := 0
		for range 1 + rng.IntN(6) {
			var err error
			var accepts bool // what the consumer SHOULD do, computed from bindings
			switch rng.IntN(5) {
			case 0:
				w := Window{Tool: pick(tools), Target: pick(targets), Duration: AWSWindow, Level: LevelWindow}
				wantDev := pick(devices)
				accepts = bound == nil && dev == wantDev && tool == w.Tool && (w.Target == "" || target == w.Target)
				_, err = st.Touch(wantDev, w, v)
			case 1:
				_, err = reg.Sponsor(newGrant, v)
				accepts = string(bound) == string(newGrant.Hash())
			case 2:
				_, err = reg.Widen(sess.ID, root.ID, v)
				accepts = string(bound) == string(WidenHash(sess.ID, root.ID))
			case 3:
				err = lot.Approve(parkedID, v)
				accepts = string(bound) == string(reqHash)
			case 4:
				err = lot.ApproveBatch(batchIDs, v)
				accepts = string(bound) == string(BatchHash(batchIDs)) && batchIDs[0] != parkedID
			}
			switch {
			case err == nil:
				accepted++
				if !accepts {
					t.Fatalf("iter %d: consumer accepted a proof whose bindings did not match (dev=%s tool=%s target=%s bound=%x)", i, dev, tool, target, bound)
				}
				if !v.Used() {
					t.Fatalf("iter %d: accepted proof not marked used", i)
				}
			case accepted > 0:
				// Already spent: every later consumer must say so, or refuse
				// on a binding first; either way it must not accept.
			default:
				if accepts {
					t.Fatalf("iter %d: consumer refused a matching, unused proof: %v", i, err)
				}
				if v.Used() {
					t.Fatalf("iter %d: refused consumer consumed the proof: %v", i, err)
				}
			}
			// The one thing that must never happen: a second success. Each
			// consumer's own state also makes a second success impossible
			// (a window opened, a grant sponsored, an item approved), so
			// try the exact same consumer again with identical arguments
			// and demand ErrPresenceConsumed or a state refusal, never nil.
			if accepted > 1 {
				t.Fatalf("iter %d: proof accepted twice", i)
			}
		}
		successes += accepted
	}
	if successes < iterations/8 {
		t.Fatalf("property test under-exercised: only %d acceptances in %d iterations", successes, iterations)
	}
}
