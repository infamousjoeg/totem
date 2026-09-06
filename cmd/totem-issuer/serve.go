package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/infamousjoeg/totem/internal/ca"
	"github.com/infamousjoeg/totem/internal/server"
)

// serve runs the front door. docs/totem-design.md: "One container, one config
// file, mTLS only", and "Every issuance, exchange, and policy change is one
// structured, hash-chained log line ... Stdout".
//
// So the audit stream IS stdout, and nothing else may write there. Every human
// message this command produces goes to stderr, because a line of prose in the
// middle of a hash-chained stream is a line a log shipper cannot parse and a
// verifier cannot place: it breaks the chain for a reader without anything
// having been tampered with, which is the worst possible false positive for a
// control whose entire job is to be believed.
func cmdServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dirFlag := fs.String("dir", "", "where issuer state lives (default "+DefaultIssuerDir+", or $TOTEM_ISSUER_DIR)")
	listen := fs.String("listen", "", "override the bind address in the config")
	if err := fs.Parse(args); err != nil {
		return failf("Run 'totem-issuer serve -h' for the list of options.", "could not read those options.")
	}
	dir := issuerDir(*dirFlag)

	rt, err := openRuntime(ctx, dir)
	if err != nil {
		return err
	}
	defer rt.Close()
	if *listen != "" {
		rt.cfg.Listen = *listen
	}

	// State the durable chain's tip, once, before serving. docs/totem-design.md
	// on truncation: the chain proves its own consistency and nothing more, so
	// detecting a rollback needs a value the attacker does not control, which
	// means this one, already off the box. The log stream leaves via syslog or
	// OTLP, so emitting it here makes that copy for free.
	//
	// It is emitted HERE rather than in openRuntime because stdout is the audit
	// stream for this command and this command only; the one-shot commands
	// print for a person on stdout, and interleaving a JSON record with that is
	// how a shipped stream acquires lines nothing can parse.
	//
	// This does not close the rollback hole and must not be read as doing so.
	// See internal/server.EventChainHead.
	if err := server.LogChainHead(ctx, rt.audit, rt.db, server.ChainHeadAtOpen); err != nil {
		return err
	}

	srv, err := newServer(rt)
	if err != nil {
		return err
	}
	identity, err := server.LoadIdentity(tlsDir(dir))
	if err != nil {
		return err
	}
	// Two things change with no method call behind them: the signing
	// intermediate is promoted on the clock, and the CA passphrase can stop
	// opening the CA after a pull-based rotation. Neither is recorded unless
	// something looks, so something looks. See internal/server/watch.go.
	passphrase, _ := rt.ca.(ca.PassphraseOperator)
	watcher, err := server.NewWatcher(server.WatcherConfig{
		CA:         rt.ca,
		Passphrase: passphrase,
		Audit:      rt.audit,
		Warn:       os.Stderr,
	})
	if err != nil {
		return err
	}
	go watcher.Run(ctx)

	fmt.Fprintf(os.Stderr, "totem-issuer: %s listening on %s (certificate sha256:%s)\n",
		rt.cfg.TrustDomain, rt.cfg.Listen, identity.FingerprintHex())
	if n := len(rt.issuer.Pending()); n > 0 {
		fmt.Fprintf(os.Stderr, "totem-issuer: %d device(s) waiting for approval\n", n)
	}
	return srv.ListenAndServe(ctx)
}
