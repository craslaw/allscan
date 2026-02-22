package main

import (
	"fmt"
	"os"
	"sort"
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
	ColorBold        = "\033[1m"
	ColorDim         = "\033[2m"
	ColorBrightGreen = "\033[92m"
)

// CoverageState represents the coverage status for a (language, scanType) pair
type CoverageState int

const (
	CoverageNone        CoverageState = iota // No scanner of this type covers this language
	CoverageConditional                      // A scanner conditionally covers this language (requires specific package manager files)
	CoverageFailed                           // A scanner covers this language but failed
	CoverageOK                               // A scanner covers this language and succeeded
)

// printSummary displays a colorful summary of all scan results
func printSummary(contexts []RepoScanContext) {
	separator := strings.Repeat("═", 70)
	thinSeparator := strings.Repeat("─", 70)

	fmt.Printf("\n%s%s%s\n", ColorCyan, separator, ColorReset)
	fmt.Printf("%s%s 📊 SCAN RESULTS SUMMARY %s%s\n", ColorBold, ColorCyan, ColorReset, ColorReset)
	fmt.Printf("%s%s%s\n\n", ColorCyan, separator, ColorReset)

	successful := 0
	failed := 0
	totalResults := 0
	totalDuration := time.Duration(0)

	// Process each repository context
	for _, ctx := range contexts {
		// Extract repo name for cleaner display
		parts := strings.Split(ctx.RepoURL, "/")
		repoName := parts[len(parts)-2] + "/" + strings.TrimSuffix(parts[len(parts)-1], ".git")

		fmt.Printf("%s%s 📦 %s%s\n", ColorBold, ColorMagenta, repoName, ColorReset)
		fmt.Printf("%s%s%s\n", ColorDim, thinSeparator, ColorReset)

		for _, result := range ctx.Results {
			totalResults++
			totalDuration += result.Duration
			if result.Success {
				successful++
			} else {
				failed++
			}

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

		// Print coverage matrix for this repo
		printCoverageMatrix(ctx)

		// Print SBOM path if generated
		if ctx.SBOMPath != "" {
			fmt.Printf("\n  %s%sSBOM%s: %s\n", ColorBold, ColorCyan, ColorReset, ctx.SBOMPath)
		}

		fmt.Println()
	}

	// Overall totals
	fmt.Printf("%s%s%s\n", ColorCyan, separator, ColorReset)
	fmt.Printf("%s%s 📈 OVERALL STATISTICS %s%s\n", ColorBold, ColorCyan, ColorReset, ColorReset)
	fmt.Printf("%s%s%s\n", ColorCyan, separator, ColorReset)

	fmt.Printf("  Total scans:    %s%d%s\n", ColorBold, totalResults, ColorReset)
	fmt.Printf("  Successful:     %s%s%d%s\n", ColorGreen, ColorBold, successful, ColorReset)
	if failed > 0 {
		fmt.Printf("  Failed:         %s%s%d%s\n", ColorRed, ColorBold, failed, ColorReset)
	} else {
		fmt.Printf("  Failed:         %s0%s\n", ColorDim, ColorReset)
	}
	fmt.Printf("  Total duration: %s%v%s\n", ColorDim, totalDuration, ColorReset)
	fmt.Printf("%s%s%s\n\n", ColorCyan, separator, ColorReset)
}

// computeCoverage builds a coverage map: language → scanType → CoverageState.
// Scanners with Type() == "Scorecard" are excluded (repo-level, not language-specific).
func computeCoverage(ctx RepoScanContext) map[string]map[string]CoverageState {
	if ctx.Languages == nil || len(ctx.Languages.Languages) == 0 {
		return nil
	}

	// Collect the scan types we care about (from parsers, excluding Scorecard)
	scanTypes := []string{"SCA", "SAST"}

	// Initialize the matrix: every (language, scanType) starts as CoverageNone
	coverage := make(map[string]map[string]CoverageState)
	for _, lang := range ctx.Languages.Languages {
		coverage[lang] = make(map[string]CoverageState)
		for _, st := range scanTypes {
			coverage[lang][st] = CoverageNone
		}
	}

	// For each scanner that was selected to run, determine which languages it covers
	for _, scanner := range ctx.Scanners {
		// Look up the parser to get the scan type
		parser, ok := parsers.Get(scanner.Name)
		if !ok {
			continue
		}
		scanType := parser.Type()

		// Skip repo-level scanners that aren't language-specific
		if scanType == "Scorecard" || scanType == "Binary" || scanType == "Secrets" {
			continue
		}

		// Skip types we don't track
		tracked := false
		for _, st := range scanTypes {
			if st == scanType {
				tracked = true
				break
			}
		}
		if !tracked {
			continue
		}

		// Determine if this scanner succeeded or failed
		scannerSuccess := false
		for _, result := range ctx.Results {
			if result.Scanner == scanner.Name {
				scannerSuccess = result.Success
				break
			}
		}

		// Determine which languages this scanner covers
		isUniversal := len(scanner.Languages) == 0
		for _, lang := range ctx.Languages.Languages {
			covers := isUniversal
			if !covers {
				for _, sl := range scanner.Languages {
					if strings.EqualFold(sl, lang) {
						covers = true
						break
					}
				}
			}

			if covers {
				current := coverage[lang][scanType]
				if scannerSuccess {
					// Success always upgrades to OK
					coverage[lang][scanType] = CoverageOK
				} else if current < CoverageFailed {
					// Failure upgrades from None/Conditional to Failed (doesn't downgrade OK)
					coverage[lang][scanType] = CoverageFailed
				}
				continue
			}

			// Check conditional language support
			for _, sl := range scanner.LanguagesConditional {
				if strings.EqualFold(sl, lang) {
					// Only upgrade from None to Conditional; don't override Failed or OK
					if coverage[lang][scanType] == CoverageNone {
						coverage[lang][scanType] = CoverageConditional
					}
					break
				}
			}
		}
	}

	return coverage
}

// printCoverageMatrix renders the language coverage table for a repo context
func printCoverageMatrix(ctx RepoScanContext) {
	coverage := computeCoverage(ctx)
	if coverage == nil {
		return
	}

	// Get percentages for labelling
	pcts := ctx.Languages.Percentages()

	// Sort languages by percentage descending (most prevalent first),
	// with alphabetical as tiebreaker
	languages := make([]string, 0, len(coverage))
	for lang := range coverage {
		languages = append(languages, lang)
	}
	sort.Slice(languages, func(i, j int) bool {
		pi, pj := pcts[languages[i]], pcts[languages[j]]
		if pi != pj {
			return pi > pj
		}
		return languages[i] < languages[j]
	})

	scanTypes := []string{"SCA", "SAST"}

	// Build percentage strings and compute widths for vertical alignment
	pctStrs := make(map[string]string, len(languages))
	maxPctWidth := 0
	maxLangNameWidth := 0
	for _, lang := range languages {
		if len(lang) > maxLangNameWidth {
			maxLangNameWidth = len(lang)
		}
		if pct, ok := pcts[lang]; ok {
			var s string
			if pct < 1.0 {
				s = "(<1%)"
			} else {
				s = fmt.Sprintf("(%d%%)", int(pct+0.5))
			}
			pctStrs[lang] = s
			if len(s) > maxPctWidth {
				maxPctWidth = len(s)
			}
		}
	}

	// Build labels: language name left-aligned, percentage right-aligned in fixed column
	labels := make(map[string]string, len(languages))
	for _, lang := range languages {
		if s, ok := pctStrs[lang]; ok {
			labels[lang] = fmt.Sprintf("%-*s %*s", maxLangNameWidth, lang, maxPctWidth, s)
		} else {
			labels[lang] = lang
		}
	}

	// Calculate column widths
	langWidth := len("Language")
	for _, lang := range languages {
		if len(labels[lang]) > langWidth {
			langWidth = len(labels[lang])
		}
	}
	colWidth := 10 // width for each scan type column

	// Print header
	fmt.Printf("\n  %s%sLanguage Coverage%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Printf("  %-*s", langWidth, "Language")
	for _, st := range scanTypes {
		fmt.Printf("  %-*s", colWidth, st)
	}
	fmt.Println()

	// Separator
	totalWidth := langWidth + len(scanTypes)*(colWidth+2)
	fmt.Printf("  %s%s%s\n", ColorDim, strings.Repeat("─", totalWidth), ColorReset)

	// Rows
	for _, lang := range languages {
		fmt.Printf("  %-*s", langWidth, labels[lang])
		for _, st := range scanTypes {
			state := coverage[lang][st]
			var cell string
			switch state {
			case CoverageOK:
				cell = fmt.Sprintf("%s✔%s", ColorBrightGreen, ColorReset)
			case CoverageFailed:
				cell = fmt.Sprintf("%s⚠%s", ColorYellow, ColorReset)
			case CoverageConditional:
				cell = fmt.Sprintf("%s◐%s", ColorYellow, ColorReset)
			default:
				cell = fmt.Sprintf("%s✘%s", ColorRed, ColorReset)
			}
			// Pad to colWidth (symbol is 1 visible char + color codes)
			fmt.Printf("  %s%*s", cell, colWidth-1, "")
		}
		fmt.Println()
	}

	// Print repo-level scanners below the table
	printRepoLevelScanners(ctx)
}

// printRepoLevelScanners lists language-agnostic scanners (Secrets, Binary, Scorecard)
// separately from the per-language coverage matrix.
func printRepoLevelScanners(ctx RepoScanContext) {
	type repoScanner struct {
		name     string
		scanType string
		success  bool
	}

	var scanners []repoScanner
	for _, scanner := range ctx.Scanners {
		parser, ok := parsers.Get(scanner.Name)
		if !ok {
			continue
		}
		scanType := parser.Type()
		if scanType != "Secrets" && scanType != "Binary" && scanType != "Scorecard" {
			continue
		}

		// Check if this scanner has a result
		found := false
		success := false
		for _, result := range ctx.Results {
			if result.Scanner == scanner.Name {
				found = true
				success = result.Success
				break
			}
		}
		if !found {
			continue
		}

		scanners = append(scanners, repoScanner{
			name:     scanner.Name,
			scanType: scanType,
			success:  success,
		})
	}

	if len(scanners) == 0 {
		return
	}

	fmt.Printf("\n  %s%sRepo-Level Scanners%s\n", ColorBold, ColorCyan, ColorReset)
	for _, s := range scanners {
		var icon string
		if s.success {
			icon = fmt.Sprintf("%s✔%s", ColorBrightGreen, ColorReset)
		} else {
			icon = fmt.Sprintf("%s⚠%s", ColorYellow, ColorReset)
		}
		fmt.Printf("  %s %s (%s%s%s)\n", icon, s.name, ColorDim, s.scanType, ColorReset)
	}
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
