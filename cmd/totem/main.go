// Command totem is the laptop agent: it holds a hardware-bound device key,
// presence-gates signing, serves the SPIFFE Workload API on a unix socket, and
// runs the per-tool bridges. Scaffold only: this main prints its version and
// exits. No device key, no socket, no attestation code yet.
package main

import (
	"fmt"

	"github.com/infamousjoeg/totem/internal/version"
)

func main() {
	fmt.Printf("totem %s (not yet functional)\n", version.Version)
}
