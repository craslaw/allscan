package main

import (
	"fmt"
	"os/exec"
)

func main() {
	fmt.Println("🔍 Vulnerability Scanner Orchestrator")

	// Test that scanners are available
	scanners := []string{"gosec", "gitleaks"}

	for _, scanner := range scanners {
		cmd := exec.Command(scanner, "--version")
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("❌ %s: not found\n", scanner)
		} else {
			fmt.Printf("✅ %s: %s\n", scanner, string(output))
		}
	}
}
