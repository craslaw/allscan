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
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorWhite   = "\033[37m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
)

// printSummary displays a colorful summary of all scan results
func printSummary(results []ScanResult) {
	separator := strings.Repeat("═", 70)
	thinSeparator := strings.Repeat("─", 70)

	fmt.Printf("\n%s%s%s\n", colorCyan, separator, colorReset)
	fmt.Printf("%s%s 📊 SCAN RESULTS SUMMARY %s%s\n", colorBold, colorCyan, colorReset, colorReset)
	fmt.Printf("%s%s%s\n\n", colorCyan, separator, colorReset)

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

		fmt.Printf("%s%s 📦 %s%s\n", colorBold, colorMagenta, repoName, colorReset)
		fmt.Printf("%s%s%s\n", colorDim, thinSeparator, colorReset)

		for _, result := range repoScans {
			if !result.Success {
				fmt.Printf("  %s❌ %s%s: %sFAILED%s - %v\n",
					colorRed, result.Scanner, colorReset, colorRed, colorReset, result.Error)
				continue
			}

			// Parse the scan output using the appropriate parser
			summary, parser := parseScanOutput(result)
			if parser != nil {
				// Scorecard gets detailed stdout output
				if parser.Type() == "Scorecard" {
					if err := parsers.PrintScorecardReport(result.OutputPath); err != nil {
						fmt.Printf("  %s❌ %s%s: %sFailed to print report%s - %v\n",
							colorRed, result.Scanner, colorReset, colorRed, colorReset, err)
					}
				} else {
					printScannerSummary(parser, summary)
				}
			} else {
				// Unknown scanner - show basic info
				fmt.Printf("  🔧 %s%s%s (%sUnknown%s)\n", colorBold, result.Scanner, colorReset, colorDim, colorReset)
				fmt.Printf("     %sNo parser available%s\n", colorDim, colorReset)
			}
		}
		fmt.Println()
	}

	// Overall totals
	fmt.Printf("%s%s%s\n", colorCyan, separator, colorReset)
	fmt.Printf("%s%s 📈 OVERALL STATISTICS %s%s\n", colorBold, colorCyan, colorReset, colorReset)
	fmt.Printf("%s%s%s\n", colorCyan, separator, colorReset)

	fmt.Printf("  Total scans:    %s%d%s\n", colorBold, len(results), colorReset)
	fmt.Printf("  Successful:     %s%s%d%s\n", colorGreen, colorBold, successful, colorReset)
	if failed > 0 {
		fmt.Printf("  Failed:         %s%s%d%s\n", colorRed, colorBold, failed, colorReset)
	} else {
		fmt.Printf("  Failed:         %s0%s\n", colorDim, colorReset)
	}
	fmt.Printf("  Total duration: %s%v%s\n", colorDim, totalDuration, colorReset)
	fmt.Printf("%s%s%s\n\n", colorCyan, separator, colorReset)
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
	fmt.Printf("  %s %s%s%s (%s%s%s)\n", icon, colorBold, scannerName, colorReset, colorDim, scanType, colorReset)

	if summary.Total == 0 {
		fmt.Printf("     %s✨ No findings%s\n", colorGreen, colorReset)
		return
	}

	// Special handling for Secrets scanners
	if scanType == "Secrets" {
		fmt.Printf("     %s🚨 Secrets detected: %d%s\n", colorRed, summary.Total, colorReset)
		return
	}

	// Build findings line for SCA/SAST
	var findings []string

	if summary.Critical > 0 {
		findings = append(findings, fmt.Sprintf("%s%s🔴 Critical: %d%s", colorRed, colorBold, summary.Critical, colorReset))
	}
	if summary.High > 0 {
		findings = append(findings, fmt.Sprintf("%s🟠 High: %d%s", colorRed, summary.High, colorReset))
	}
	if summary.Medium > 0 {
		findings = append(findings, fmt.Sprintf("%s🟡 Medium: %d%s", colorYellow, summary.Medium, colorReset))
	}
	if summary.Low > 0 {
		findings = append(findings, fmt.Sprintf("%s🟢 Low: %d%s", colorGreen, summary.Low, colorReset))
	}
	if summary.Info > 0 {
		findings = append(findings, fmt.Sprintf("%s⚪ Info: %d%s", colorDim, summary.Info, colorReset))
	}

	// Print findings
	fmt.Printf("     %s\n", strings.Join(findings, "  "))
	fmt.Printf("     %sTotal: %d findings%s\n", colorDim, summary.Total, colorReset)
}
