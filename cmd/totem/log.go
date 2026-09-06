package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/infamousjoeg/totem/internal/workloadapi"
)

// cmdLog reads back the agent's local record. docs/totem-design.md
// "Experience": totem log records refusals, prompts, and failures by default;
// successes are counted, not listed, and --verbose opts into the full record.
// Calling tools swallow helper stderr, so this file is where a refusal is
// actually legible after the fact.
func cmdLog(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	verbose := fs.Bool("verbose", false, "include every successful request, not just a count")
	limit := fs.Int("n", 50, "how many entries to show")
	if err := fs.Parse(args); err != nil {
		return failf("Run 'totem log'.", "could not read those options.")
	}

	events, err := workloadapi.ReadEvents("", 0)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		fmt.Println("Nothing yet. totem has not refused, asked, or failed at anything on this machine.")
		return nil
	}

	var shown []workloadapi.Event
	successes := 0
	for _, ev := range events {
		if ev.Kind == workloadapi.KindIssuance && !*verbose {
			successes++
			continue
		}
		shown = append(shown, ev)
	}
	if *limit > 0 && len(shown) > *limit {
		shown = shown[len(shown)-*limit:]
	}

	for _, ev := range shown {
		when := ev.Time.Local().Format("Jan 02 15:04:05")
		who := ev.Tool
		if who == "" {
			who = "-"
		}
		fmt.Printf("%s  %-9s %-10s %s\n", when, ev.Kind, who, ev.Message)
		if ev.Fix != "" {
			fmt.Printf("%s  %s\n", spaces(len(when)), ev.Fix)
		}
	}
	if successes > 0 {
		fmt.Println()
		fmt.Printf("%d successful requests are not listed. Run 'totem log --verbose' to see them.\n", successes)
	}
	if len(shown) == 0 {
		fmt.Println("Nothing was refused. Run 'totem log --verbose' to see what succeeded.")
	}
	return nil
}

func spaces(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = ' '
	}
	return string(b)
}
