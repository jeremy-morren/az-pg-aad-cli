// Command azpgaad manages Microsoft Entra roles on Azure Database for PostgreSQL.
package main

import (
	"os"

	"github.com/jeremy-morren/az-pg-aad-cli/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=<tag>".
var version = "dev"

func main() {
	// cli.Run recovers panics and maps every outcome to an exit code; this is the only
	// os.Exit in the program.
	os.Exit(cli.New(version).Run(os.Args[1:]))
}
