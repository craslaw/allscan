package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"vuln-scanner-orchestrator/parsers"
)

// ANSI color codes for terminal output
const (
	ColorReset   = "\033[0m"
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorWhite   = "\033[37m"
	ColorBold    = "\033[1m"
	ColorDim     = "\033[2m"
)

// printSummary displays a colorful summary of all scan results
func printSummary(results []ScanResult) {
	separator := strings.Repeat("═", 70)
	thinSeparator := strings.Repeat("─", 70)

	fmt.Printf("\n%s%s%s\n", ColorCyan, separator, ColorReset)
	fmt.Printf("%s%s 📊 SCAN RESULTS SUMMARY %s%s\n", ColorBold, ColorCyan, ColorReset, ColorReset)
	fmt.Printf("%s%s%s\n\n", ColorCyan, separator, ColorReset)

	successful := 0
	failed := 0
	totalDuration := time.Duration(0)

	// Group results by repository
	repoResults := make(map[string][]ScanResult)
	for _, result := range results {
		repoResults[result.Repository] = append(repoResults[result.Repository], result)
		totalDuration += result.Duration
		if result.Success {
			successful++
		} else {
			failed++
		}
	}

	// Process each repository
	for repo, repoScans := range repoResults {
		// Extract repo name for cleaner display
		parts := strings.Split(repo, "/")
		repoName := parts[len(parts)-2] + "/" + strings.TrimSuffix(parts[len(parts)-1], ".git")

		fmt.Printf("%s%s 📦 %s%s\n", ColorBold, ColorMagenta, repoName, ColorReset)
		fmt.Printf("%s%s%s\n", ColorDim, thinSeparator, ColorReset)

		for _, result := range repoScans {
			if !result.Success {
				fmt.Printf("  %s❌ %s%s: %sFAILED%s - %v\n",
					ColorRed, result.Scanner, ColorReset, ColorRed, ColorReset, result.Error)
				continue
			}

			// Parse the scan output using the appropriate parser
			summary, parser := parseScanOutput(result)
			if parser != nil {
				// Scorecard gets detailed stdout output
				if parser.Type() == "Scorecard" {
					if err := parsers.PrintScorecardReport(result.OutputPath); err != nil {
						fmt.Printf("  %s❌ %s%s: %sFailed to print report%s - %v\n",
							ColorRed, result.Scanner, ColorReset, ColorRed, ColorReset, err)
					}
				} else {
					printScannerSummary(parser, summary)
				}
			} else {
				// Unknown scanner - show basic info
				fmt.Printf("  🔧 %s%s%s (%sUnknown%s)\n", ColorBold, result.Scanner, ColorReset, ColorDim, ColorReset)
				fmt.Printf("     %sNo parser available%s\n", ColorDim, ColorReset)
			}
		}
		fmt.Println()
	}

	// Overall totals
	fmt.Printf("%s%s%s\n", ColorCyan, separator, ColorReset)
	fmt.Printf("%s%s 📈 OVERALL STATISTICS %s%s\n", ColorBold, ColorCyan, ColorReset, ColorReset)
	fmt.Printf("%s%s%s\n", ColorCyan, separator, ColorReset)

	fmt.Printf("  Total scans:    %s%d%s\n", ColorBold, len(results), ColorReset)
	fmt.Printf("  Successful:     %s%s%d%s\n", ColorGreen, ColorBold, successful, ColorReset)
	if failed > 0 {
		fmt.Printf("  Failed:         %s%s%d%s\n", ColorRed, ColorBold, failed, ColorReset)
	} else {
		fmt.Printf("  Failed:         %s0%s\n", ColorDim, ColorReset)
	}
	fmt.Printf("  Total duration: %s%v%s\n", ColorDim, totalDuration, ColorReset)
	fmt.Printf("%s%s%s\n\n", ColorCyan, separator, ColorReset)
}

// parseScanOutput reads a scan result file and parses it using the appropriate parser
func parseScanOutput(result ScanResult) (parsers.FindingSummary, parsers.ResultParser) {
	var summary parsers.FindingSummary

	parser, ok := parsers.Get(result.Scanner)
	if !ok {
		return summary, nil
	}

	data, err := os.ReadFile(result.OutputPath)
	if err != nil {
		return summary, parser
	}

	summary, _ = parser.Parse(data)
	return summary, parser
}

// printScannerSummary displays findings for a single scanner
func printScannerSummary(parser parsers.ResultParser, summary parsers.FindingSummary) {
	// Use parser metadata for display
	icon := parser.Icon()
	scanType := parser.Type()
	scannerName := parser.Name()

	// Scanner header
	fmt.Printf("  %s %s%s%s (%s%s%s)\n", icon, ColorBold, scannerName, ColorReset, ColorDim, scanType, ColorReset)

	if summary.Total == 0 {
		fmt.Printf("     %s✨ No findings%s\n", ColorGreen, ColorReset)
		return
	}

	// Special handling for Secrets scanners
	if scanType == "Secrets" {
		fmt.Printf("     %s🚨 Secrets detected: %d%s\n", ColorRed, summary.Total, ColorReset)
		return
	}

	// Build findings line for SCA/SAST
	var findings []string

	if summary.Critical > 0 {
		findings = append(findings, fmt.Sprintf("%s%s🔴 Critical: %d%s", ColorRed, ColorBold, summary.Critical, ColorReset))
	}
	if summary.High > 0 {
		findings = append(findings, fmt.Sprintf("%s🟠 High: %d%s", ColorRed, summary.High, ColorReset))
	}
	if summary.Medium > 0 {
		findings = append(findings, fmt.Sprintf("%s🟡 Medium: %d%s", ColorYellow, summary.Medium, ColorReset))
	}
	if summary.Low > 0 {
		findings = append(findings, fmt.Sprintf("%s🟢 Low: %d%s", ColorGreen, summary.Low, ColorReset))
	}
	if summary.Info > 0 {
		findings = append(findings, fmt.Sprintf("%s⚪ Info: %d%s", ColorDim, summary.Info, ColorReset))
	}

	// Print findings
	fmt.Printf("     %s\n", strings.Join(findings, "  "))
	fmt.Printf("     %sTotal: %d findings%s\n", ColorDim, summary.Total, ColorReset)
}
