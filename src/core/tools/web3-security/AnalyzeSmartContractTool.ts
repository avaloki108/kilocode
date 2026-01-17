// kilocode_change - new file

/**
 * Analyze Smart Contract Tool
 *
 * This module provides a VS Code tool for analyzing smart contracts
 * using the Web3 Security Platform's multi-agent system.
 *
 * @see WEB3-SECURITY-PLATFORM-ARCHITECTURE.md
 */

import * as vscode from "vscode"
import type { VulnerabilityReport } from "../../../packages/core-schemas/src/web3-security/vulnerability.js"
import type { AnalysisContext, AnalysisResult } from "../../../packages/core-schemas/src/web3-security/analysis.js"
import { Web3SecurityHub } from "../../../services/web3-security/Web3SecurityHub.js"
import { AgentOrchestrator } from "../../../services/web3-security/orchestration/AgentOrchestrator.js"

/**
 * Analyze Smart Contract Tool Parameters
 */
export interface AnalyzeSmartContractParams {
	/** Contract file path */
	contractPath: string
	/** Chain type */
	chainType?: "evm" | "solana"
	/** Analysis depth */
	analysisDepth?: "quick" | "standard" | "deep"
	/** Tools to use */
	tools?: string[]
	/** Enable fuzzing */
	enableFuzzing?: boolean
	/** Enable symbolic execution */
	enableSymbolicExecution?: boolean
	/** Enable pattern detection */
	enablePatternDetection?: boolean
	/** Output format */
	outputFormat?: "json" | "markdown" | "html"
}

/**
 * Analyze Smart Contract Tool
 */
export class AnalyzeSmartContractTool {
	private securityHub: Web3SecurityHub
	private orchestrator: AgentOrchestrator

	constructor(securityHub: Web3SecurityHub, orchestrator: AgentOrchestrator) {
		this.securityHub = securityHub
		this.orchestrator = orchestrator
	}

	/**
	 * Analyze a smart contract
	 */
	async analyze(params: AnalyzeSmartContractParams): Promise<AnalysisResult> {
		// Create analysis context
		const context: AnalysisContext = {
			analysisId: this.generateAnalysisId(),
			contractPath: params.contractPath,
			chainType: params.chainType || "evm",
			status: "initializing",
			phases: [],
			toolStatuses: [],
			vulnerabilities: [],
			summary: {
				total: 0,
				critical: 0,
				high: 0,
				medium: 0,
				low: 0,
				informational: 0,
			},
		}

		// Add initial phase
		context.phases.push({
			name: "Initialization",
			status: "in_progress",
			startTime: new Date().toISOString(),
		})

		// Determine which tools to use
		const toolsToUse = this.determineTools(params)

		// Run static analysis
		if (
			toolsToUse.includes("slither") ||
			toolsToUse.includes("mythril") ||
			toolsToUse.includes("aderyn") ||
			toolsToUse.includes("crytic")
		) {
			context.phases.push({
				name: "Static Analysis",
				status: "in_progress",
				startTime: new Date().toISOString(),
			})

			const staticResult = await this.securityHub.analyzeContract({
				contractPath: params.contractPath,
				tools: toolsToUse.filter((t) => ["slither", "mythril", "aderyn", "crytic"].includes(t)),
			})

			this.updateContextFromResult(context, staticResult)
		}

		// Run fuzzing tests
		if (
			params.enableFuzzing &&
			(toolsToUse.includes("foundry") || toolsToUse.includes("hardhat") || toolsToUse.includes("echidna"))
		) {
			context.phases.push({
				name: "Fuzzing",
				status: "in_progress",
				startTime: new Date().toISOString(),
			})

			const fuzzingTools = toolsToUse.filter((t) => ["foundry", "hardhat", "echidna"].includes(t))

			const fuzzingResult = await this.securityHub.analyzeContract({
				contractPath: params.contractPath,
				tools: fuzzingTools,
			})

			this.updateContextFromResult(context, fuzzingResult)
		}

		// Run symbolic execution
		if (params.enableSymbolicExecution && (toolsToUse.includes("manticore") || toolsToUse.includes("maian"))) {
			context.phases.push({
				name: "Symbolic Execution",
				status: "in_progress",
				startTime: new Date().toISOString(),
			})

			const symbolicTools = toolsToUse.filter((t) => ["manticore", "maian"].includes(t))

			const symbolicResult = await this.securityHub.analyzeContract({
				contractPath: params.contractPath,
				tools: symbolicTools,
			})

			this.updateContextFromResult(context, symbolicResult)
		}

		// Run pattern detection
		if (params.enablePatternDetection) {
			context.phases.push({
				name: "Pattern Detection",
				status: "in_progress",
				startTime: new Date().toISOString(),
			})

			const patternResult = await this.orchestrator.analyzeContract({
				contractPath: params.contractPath,
				analysisContext: context,
				tools: ["reentrancy", "arithmetic", "access_control", "front_running", "logic_error", "solana"],
			})

			this.updateContextFromResult(context, patternResult)
		}

		// Update final status
		context.status = "completed"
		context.endTime = new Date().toISOString()

		// Generate report
		let report: VulnerabilityReport | null

		if (params.outputFormat === "json") {
			report = this.generateJSONReport(context)
		} else if (params.outputFormat === "markdown") {
			report = this.generateMarkdownReport(context)
		} else if (params.outputFormat === "html") {
			report = this.generateHTMLReport(context)
		}

		// Show results
		this.showResults(context, report)

		return {
			analysisId: context.analysisId,
			target: {
				name: params.contractPath,
				language: "solidity",
				version: "0.8.0",
				sourceCode: "",
				filePath: params.contractPath,
			},
			timestamp: new Date().toISOString(),
			vulnerabilities: context.vulnerabilities,
			summary: context.summary,
		}
	}

	/**
	 * Determine which tools to use
	 */
	private determineTools(params: AnalyzeSmartContractParams): string[] {
		const tools: string[] = []

		if (params.tools && params.tools.length > 0) {
			return params.tools
		}

		// Use all tools if none specified
		if (params.enableFuzzing) {
			tools.push("foundry", "hardhat", "echidna")
		}

		if (params.enableSymbolicExecution) {
			tools.push("manticore", "maian")
		}

		if (params.enablePatternDetection) {
			tools.push("slither", "mythril", "aderyn", "crytic")
		}

		// Default to static analysis
		if (tools.length === 0) {
			tools.push("slither")
		}

		return tools
	}

	/**
	 * Update context from analysis result
	 */
	private updateContextFromResult(context: AnalysisContext, result: AnalysisResult): void {
		// Update vulnerabilities
		if (result.vulnerabilities) {
			context.vulnerabilities.push(...result.vulnerabilities)
		}

		// Update summary
		if (result.summary) {
			context.summary = {
				total: (context.summary.total || 0) + (result.summary.total || 0),
				critical: (context.summary.critical || 0) + (result.summary.critical || 0),
				high: (context.summary.high || 0) + (result.summary.high || 0),
				medium: (context.summary.medium || 0) + (result.summary.medium || 0),
				low: (context.summary.low || 0) + (result.summary.low || 0),
				informational: (context.summary.informational || 0) + (result.summary.informational || 0),
			}
		}

		// Update tool statuses
		if (result.toolStatuses) {
			context.toolStatuses.push(...result.toolStatuses)
		}
	}

	/**
	 * Generate JSON report
	 */
	private generateJSONReport(context: AnalysisContext): VulnerabilityReport {
		return {
			analysisId: context.analysisId,
			timestamp: new Date().toISOString(),
			contractPath: context.contractPath,
			chainType: context.chainType,
			vulnerabilities: context.vulnerabilities,
			summary: context.summary,
			format: "json",
		}
	}

	/**
	 * Generate Markdown report
	 */
	private generateMarkdownReport(context: AnalysisContext): VulnerabilityReport {
		const markdown = this.buildMarkdownReport(context)

		return {
			analysisId: context.analysisId,
			timestamp: new Date().toISOString(),
			contractPath: context.contractPath,
			chainType: context.chainType,
			vulnerabilities: context.vulnerabilities,
			summary: context.summary,
			format: "markdown",
			content: markdown,
		}
	}

	/**
	 * Build Markdown report
	 */
	private buildMarkdownReport(context: AnalysisContext): string {
		const lines: string[] = []

		lines.push("# Smart Contract Security Analysis Report")
		lines.push("")
		lines.push(`**Analysis ID:** ${context.analysisId}`)
		lines.push("")
		lines.push(`**Contract:** ${context.contractPath}`)
		lines.push("")
		lines.push(`**Chain Type:** ${context.chainType}`)
		lines.push("")
		lines.push(`**Analysis Date:** ${new Date().toISOString()}`)
		lines.push("")
		lines.push("---")
		lines.push("## Summary")
		lines.push("")
		lines.push(`- **Total Vulnerabilities:** ${context.summary.total}`)
		lines.push(`  - **Critical:** ${context.summary.critical}`)
		lines.push(`  - **High:** ${context.summary.high}`)
		lines.push(`  - **Medium:** ${context.summary.medium}`)
		lines.push(`  - **Low:** ${context.summary.low}`)
		lines.push(`  - **Informational:** ${context.summary.informational}`)
		lines.push("")
		lines.push("## Vulnerabilities")

		// Group vulnerabilities by severity
		const criticalVulns = context.vulnerabilities.filter((v) => v.severity === "critical")
		const highVulns = context.vulnerabilities.filter((v) => v.severity === "high")
		const mediumVulns = context.vulnerabilities.filter((v) => v.severity === "medium")
		const lowVulns = context.vulnerabilities.filter((v) => v.severity === "low")
		const informationalVulns = context.vulnerabilities.filter((v) => v.severity === "informational")

		if (criticalVulns.length > 0) {
			lines.push("")
			lines.push("### Critical")
			for (const vuln of criticalVulns) {
				lines.push(`- [${vuln.id}] ${vuln.title}`)
				lines.push(`  - **Category:** ${vuln.category}`)
				lines.push(`  - **Severity:** ${vuln.severity}`)
				lines.push(`  - **Source:** ${vuln.source}`)
				if (vuln.locations && vuln.locations.length > 0) {
					lines.push(`  - **Location:** ${vuln.locations[0].file}:${vuln.locations[0].line}`)
				}
				lines.push("")
			}
		}

		if (highVulns.length > 0) {
			lines.push("")
			lines.push("### High")
			for (const vuln of highVulns) {
				lines.push(`- [${vuln.id}] ${vuln.title}`)
				lines.push(`  - **Category:** ${vuln.category}`)
				lines.push(`  - **Severity:** ${vuln.severity}`)
				lines.push(`  - **Source:** ${vuln.source}`)
				if (vuln.locations && vuln.locations.length > 0) {
					lines.push(`  - **Location:** ${vuln.locations[0].file}:${vuln.locations[0].line}`)
				}
				lines.push("")
			}
		}

		if (mediumVulns.length > 0) {
			lines.push("")
			lines.push("### Medium")
			for (const vuln of mediumVulns) {
				lines.push(`- [${vuln.id}] ${vuln.title}`)
				lines.push(`  - **Category:** ${vuln.category}`)
				lines.push(`  - **Severity:** ${vuln.severity}`)
				lines.push(`  - **Source:** ${vuln.source}`)
				if (vuln.locations && vuln.locations.length > 0) {
					lines.push(`  - **Location:** ${vuln.locations[0].file}:${vuln.locations[0].line}`)
				}
				lines.push("")
			}
		}

		if (lowVulns.length > 0) {
			lines.push("")
			lines.push("### Low")
			for (const vuln of lowVulns) {
				lines.push(`- [${vuln.id}] ${vuln.title}`)
				lines.push(`  - **Category:** ${vuln.category}`)
				lines.push(`  - **Severity:** ${vuln.severity}`)
				lines.push(`  - **Source:** ${vuln.source}`)
				if (vuln.locations && vuln.locations.length > 0) {
					lines.push(`  - **Location:** ${vuln.locations[0].file}:${vuln.locations[0].line}`)
				}
				lines.push("")
			}
		}

		if (informationalVulns.length > 0) {
			lines.push("")
			lines.push("### Informational")
			for (const vuln of informationalVulns) {
				lines.push(`- [${vuln.id}] ${vuln.title}`)
				lines.push(`  - **Category:** ${vuln.category}`)
				lines.push(`  - **Severity:** ${vuln.severity}`)
				lines.push(`  - **Source:** ${vuln.source}`)
				if (vuln.locations && vuln.locations.length > 0) {
					lines.push(`  - **Location:** ${vuln.locations[0].file}:${vuln.locations[0].line}`)
				}
				lines.push("")
			}
		}

		return lines.join("\n")
	}

	/**
	 * Generate HTML report
	 */
	private generateHTMLReport(context: AnalysisContext): VulnerabilityReport {
		const markdown = this.buildMarkdownReport(context)

		return {
			analysisId: context.analysisId,
			timestamp: new Date().toISOString(),
			contractPath: context.contractPath,
			chainType: context.chainType,
			vulnerabilities: context.vulnerabilities,
			summary: context.summary,
			format: "html",
			content: this.markdownToHTML(markdown),
		}
	}

	/**
	 * Convert Markdown to HTML
	 */
	private markdownToHTML(markdown: string): string {
		// Simple Markdown to HTML conversion
		let html = markdown

		// Convert headers
		html = html.replace(/^# (.*$)/gm, "<h1>$1</h1>")
		html = html.replace(/^## (.*$)/gm, "<h2>$1</h2>")

		// Convert bold
		html = html.replace(/\*\*(.*?)\*/g, "<strong>$1</strong>")

		// Convert code blocks
		html = html.replace(/```(\w*?\n)?([\s\S]*?)```/g, "<pre><code>$1</code></pre>")

		// Convert lists
		html = html.replace(/^- (.+)$/gm, "<ul><li>$1</li></ul>")

		// Convert line breaks
		html = html.replace(/\n\n/g, "<br>")

		return html
	}

	/**
	 * Show results to user
	 */
	private showResults(context: AnalysisContext, report: VulnerabilityReport): void {
		// Create output panel
		const panel = vscode.window.createWebviewPanel("web3SecurityResults")

		// Set HTML content
		panel.webview.html = this.markdownToHTML(report.content)

		// Show panel
		panel.reveal(vscode.ViewColumn.One)

		// Store context for potential follow-up actions
		const contextData = JSON.stringify(context, null, 2)
		panel.webview.postMessage({
			command: "setContext",
			data: contextData,
		})
	}

	/**
	 * Generate analysis ID
	 */
	private generateAnalysisId(): string {
		return `analyze-${Date.now()}-${Math.random().toString(36).substring(7)}`
	}
}
