// Command totem-issuer is the broker: a headless box, never the laptop, that
// holds the CA and the exchange references and mints short-lived, device- and
// tool-scoped credentials only after a present human. Scaffold only: this main
// prints its version and exits. No CA, no exchanges, no presence policy yet.
package main

import (
	"fmt"

	"github.com/infamousjoeg/totem/internal/version"
)

func main() {
	fmt.Printf("totem-issuer %s (not yet functional)\n", version.Version)
}
