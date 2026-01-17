// kilocode_change - new file

/**
 * Foundry Integration
 *
 * This module provides integration with Foundry for smart contract testing,
 * fuzzing, and verification. Foundry is a fast, portable, and modular
 * toolkit for Ethereum application development.
 *
 * @see https://getfoundry.sh/
 */

import type { Vulnerability, CodeLocation } from "../../packages/core-schemas/src/web3-security/vulnerability.js"
import type {
	AnalysisResult,
	SmartContract,
	AnalysisContext,
} from "../../packages/core-schemas/src/web3-security/analysis.js"

/**
 * Foundry test result
 */
export interface FoundryTestResult {
	/** Test name */
	name: string
	/** Test status: pass, fail, skip, or revert */
	status: "pass" | "fail" | "skip" | "revert"
	/** Test execution time in seconds */
	duration: number
	/** Gas used by the test */
	gasUsed?: number
	/** Error message if test failed */
	error?: string
	/** Stack trace if test failed */
	stackTrace?: string
	/** Test file path */
	file: string
	/** Line number of the test */
	line: number
}

/**
 * Foundry fuzz test result
 */
export interface FoundryFuzzResult extends FoundryTestResult {
	/** Number of fuzz runs */
	runs: number
	/** Number of unique inputs tested */
	uniqueInputs: number
	/** Failing input that triggered the bug */
	failingInput?: string
	/** Seed used for fuzzing */
	seed: string
}

/**
 * Foundry coverage result
 */
export interface FoundryCoverageResult {
	/** Contract name */
	contract: string
	/** Function name */
	function: string
	/** Lines covered */
	linesCovered: number
	/** Total lines */
	totalLines: number
	/** Percentage coverage */
	coverage: number
	/** Branches covered */
	branchesCovered: number
	/** Total branches */
	totalBranches: number
}

/**
 * Foundry analysis result
 */
export interface FoundryResult {
	/** Analysis ID */
	analysisId: string
	/** Target contract */
	target: SmartContract
	/** Analysis timestamp */
	timestamp: string
	/** Test results */
	tests: FoundryTestResult[]
	/** Fuzz test results */
	fuzzTests: FoundryFuzzResult[]
	/** Coverage results */
	coverage: FoundryCoverageResult[]
	/** Overall statistics */
	statistics: {
		/** Total tests run */
		totalTests: number
		/** Tests passed */
		passed: number
		/** Tests failed */
		failed: number
		/** Tests skipped */
		skipped: number
		/** Total fuzz runs */
		totalFuzzRuns: number
		/** Overall coverage percentage */
		overallCoverage: number
	}
	/** Vulnerabilities detected */
	vulnerabilities: Vulnerability[]
	/** Raw output from Foundry */
	rawOutput: string
}

/**
 * Foundry analysis configuration
 */
export interface FoundryAnalysisConfig {
	/** Working directory for Foundry */
	workingDir: string
	/** Target contract or test file */
	target: string
	/** Fuzz test configuration */
	fuzzing?: {
		/** Number of fuzz runs per test */
		runs?: number
		/** Maximum test depth */
		maxDepth?: number
		/** Seed for deterministic fuzzing */
		seed?: string
		/** Dictionary for fuzzing */
		dictionary?: string[]
	}
	/** Test configuration */
	tests?: {
		/** Specific test to run */
		testName?: string
		/** Test pattern to match */
		testPattern?: string
		/** Verbosity level */
		verbosity?: number
	}
	/** Coverage configuration */
	coverage?: {
		/** Enable coverage collection */
		enabled?: boolean
		/** Coverage report format (lcov, html, json) */
		format?: "lcov" | "html" | "json"
	}
	/** Gas snapshot configuration */
	gasSnapshot?: {
		/** Enable gas snapshot */
		enabled?: boolean
		/** Compare against previous snapshot */
		compare?: boolean
	}
	/** RPC endpoint for fork testing */
	fork?: {
		/** RPC URL */
		url?: string
		/** Block number to fork from */
		blockNumber?: number
		/** Forking mode (all, none, or specific) */
		mode?: "all" | "none" | "specific"
	}
}

/**
 * Foundry Integration Service
 */
export class FoundryIntegration {
	private foundryPath: string
	private workingDir: string

	constructor(config: { foundryPath?: string; workingDir: string }) {
		this.foundryPath = config.foundryPath || "forge"
		this.workingDir = config.workingDir
	}

	/**
	 * Run Foundry tests
	 */
	async runTests(config: FoundryAnalysisConfig): Promise<FoundryResult> {
		const analysisId = this.generateAnalysisId()

		// Build command
		const command = this.buildTestCommand(config)

		// Execute command
		const result = await this.executeCommand(command)

		// Parse results
		const testResults = this.parseTestResults(result.stdout)
		const fuzzResults = this.parseFuzzResults(result.stdout)
		const coverage = config.coverage?.enabled ? this.parseCoverageResults(result.stdout) : []
		const vulnerabilities = this.detectVulnerabilities(testResults, fuzzResults, coverage)

		// Calculate statistics
		const statistics = this.calculateStatistics(testResults, fuzzResults, coverage)

		return {
			analysisId,
			target: {
				name: config.target,
				language: "solidity",
				version: "0.8.0",
				sourceCode: "",
				filePath: config.target,
			},
			timestamp: new Date().toISOString(),
			tests: testResults,
			fuzzTests: fuzzResults,
			coverage,
			statistics,
			vulnerabilities,
			rawOutput: result.stdout,
		}
	}

	/**
	 * Run Foundry fuzz tests
	 */
	async runFuzzTests(config: FoundryAnalysisConfig): Promise<FoundryResult> {
		const fuzzConfig = {
			...config,
			fuzzing: {
				runs: config.fuzzing?.runs || 256,
				maxDepth: config.fuzzing?.maxDepth || 100,
				seed: config.fuzzing?.seed || Math.random().toString(36).substring(7),
				dictionary: config.fuzzing?.dictionary || [],
			},
		}

		return this.runTests(fuzzConfig)
	}

	/**
	 * Generate coverage report
	 */
	async generateCoverage(config: FoundryAnalysisConfig): Promise<FoundryResult> {
		const coverageConfig = {
			...config,
			coverage: {
				enabled: true,
				format: config.coverage?.format || "json",
			},
		}

		return this.runTests(coverageConfig)
	}

	/**
	 * Run gas snapshot
	 */
	async runGasSnapshot(config: FoundryAnalysisConfig): Promise<FoundryResult> {
		const command = `${this.foundryPath} snapshot --json`

		const result = await this.executeCommand(command, config.workingDir)

		// Parse gas snapshot results
		const snapshotResults = this.parseGasSnapshotResults(result.stdout)

		return {
			analysisId: this.generateAnalysisId(),
			target: {
				name: config.target,
				language: "solidity",
				version: "0.8.0",
				sourceCode: "",
				filePath: config.target,
			},
			timestamp: new Date().toISOString(),
			tests: [],
			fuzzTests: [],
			coverage: [],
			statistics: {
				totalTests: 0,
				passed: 0,
				failed: 0,
				skipped: 0,
				totalFuzzRuns: 0,
				overallCoverage: 0,
			},
			vulnerabilities: [],
			rawOutput: result.stdout,
		}
	}

	/**
	 * Build test command
	 */
	private buildTestCommand(config: FoundryAnalysisConfig): string {
		const parts = [this.foundryPath, "test"]

		// Add target
		if (config.target) {
			parts.push(config.target)
		}

		// Add fuzzing options
		if (config.fuzzing) {
			if (config.fuzzing.runs) {
				parts.push(`-fuzz-runs ${config.fuzzing.runs}`)
			}
			if (config.fuzzing.seed) {
				parts.push(`-fuzz-seed ${config.fuzzing.seed}`)
			}
		}

		// Add test options
		if (config.tests) {
			if (config.tests.testName) {
				parts.push(`--match-test ${config.tests.testName}`)
			}
			if (config.tests.testPattern) {
				parts.push(`--match-path ${config.tests.testPattern}`)
			}
			if (config.tests.verbosity) {
				parts.push(`-v ${config.tests.verbosity}`)
			}
		}

		// Add coverage options
		if (config.coverage?.enabled) {
			parts.push("--coverage")
			if (config.coverage.format) {
				parts.push(`--report ${config.coverage.format}`)
			}
		}

		// Add gas snapshot options
		if (config.gasSnapshot?.enabled) {
			parts.push("--gas-report")
		}

		// Add fork options
		if (config.fork?.url) {
			parts.push(`--fork-url ${config.fork.url}`)
			if (config.fork.blockNumber) {
				parts.push(`--fork-block-number ${config.fork.blockNumber}`)
			}
		}

		// Add JSON output
		parts.push("--json")

		return parts.join(" ")
	}

	/**
	 * Execute command
	 */
	private async executeCommand(
		command: string,
		workingDir?: string,
	): Promise<{ stdout: string; stderr: string; exitCode: number }> {
		// This is a placeholder - actual implementation would use child_process
		// For now, return mock data
		return {
			stdout: JSON.stringify({
				test_results: [
					{
						name: "testExample",
						status: "pass",
						duration: 0.1,
						gasUsed: 100000,
						file: "test/Example.t.sol",
						line: 10,
					},
				],
			}),
			stderr: "",
			exitCode: 0,
		}
	}

	/**
	 * Parse test results
	 */
	private parseTestResults(output: string): FoundryTestResult[] {
		try {
			const data = JSON.parse(output)
			return (data.test_results || []).map((test: any) => ({
				name: test.name,
				status: test.status,
				duration: test.duration,
				gasUsed: test.gasUsed,
				error: test.error,
				stackTrace: test.stackTrace,
				file: test.file,
				line: test.line,
			}))
		} catch (error) {
			console.error("Failed to parse Foundry test results:", error)
			return []
		}
	}

	/**
	 * Parse fuzz test results
	 */
	private parseFuzzResults(output: string): FoundryFuzzResult[] {
		try {
			const data = JSON.parse(output)
			return (data.fuzz_results || []).map((test: any) => ({
				...test,
				runs: test.runs || 0,
				uniqueInputs: test.uniqueInputs || 0,
				seed: test.seed || "",
			}))
		} catch (error) {
			console.error("Failed to parse Foundry fuzz results:", error)
			return []
		}
	}

	/**
	 * Parse coverage results
	 */
	private parseCoverageResults(output: string): FoundryCoverageResult[] {
		try {
			const data = JSON.parse(output)
			return (data.coverage || []).map((cov: any) => ({
				contract: cov.contract,
				function: cov.function,
				linesCovered: cov.linesCovered,
				totalLines: cov.totalLines,
				coverage: cov.coverage,
				branchesCovered: cov.branchesCovered,
				totalBranches: cov.totalBranches,
			}))
		} catch (error) {
			console.error("Failed to parse Foundry coverage results:", error)
			return []
		}
	}

	/**
	 * Parse gas snapshot results
	 */
	private parseGasSnapshotResults(output: string): any[] {
		try {
			const data = JSON.parse(output)
			return data.gas_snapshot || []
		} catch (error) {
			console.error("Failed to parse Foundry gas snapshot results:", error)
			return []
		}
	}

	/**
	 * Detect vulnerabilities from test results
	 */
	private detectVulnerabilities(
		testResults: FoundryTestResult[],
		fuzzResults: FoundryFuzzResult[],
		coverage: FoundryCoverageResult[],
	): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Detect failed tests
		for (const test of testResults.filter((t) => t.status === "fail")) {
			vulnerabilities.push({
				id: `foundry-test-fail-${test.name}`,
				source: "foundry",
				severity: "medium",
				category: "logic_error",
				title: "Test Failure",
				description: `Test ${test.name} failed: ${test.error || "Unknown error"}`,
				locations: [
					{
						file: test.file,
						line: test.line,
						column: 0,
					},
				],
			})
		}

		// Detect fuzz test failures
		for (const fuzz of fuzzResults.filter((f) => f.status === "fail")) {
			vulnerabilities.push({
				id: `foundry-fuzz-fail-${fuzz.name}`,
				source: "foundry",
				severity: "high",
				category: "logic_error",
				title: "Fuzz Test Failure",
				description: `Fuzz test ${fuzz.name} failed with input: ${fuzz.failingInput || "Unknown"}`,
				locations: [
					{
						file: fuzz.file,
						line: fuzz.line,
						column: 0,
					},
				],
			})
		}

		// Detect low coverage
		for (const cov of coverage.filter((c) => c.coverage < 50)) {
			vulnerabilities.push({
				id: `foundry-low-coverage-${cov.contract}-${cov.function}`,
				source: "foundry",
				severity: "low",
				category: "logic_error",
				title: "Low Code Coverage",
				description: `Function ${cov.function} in contract ${cov.contract} has only ${cov.coverage}% coverage`,
				locations: [
					{
						file: cov.contract,
						line: 0,
						column: 0,
					},
				],
			})
		}

		return vulnerabilities
	}

	/**
	 * Calculate statistics
	 */
	private calculateStatistics(
		testResults: FoundryTestResult[],
		fuzzResults: FoundryFuzzResult[],
		coverage: FoundryCoverageResult[],
	) {
		const totalTests = testResults.length
		const passed = testResults.filter((t) => t.status === "pass").length
		const failed = testResults.filter((t) => t.status === "fail").length
		const skipped = testResults.filter((t) => t.status === "skip").length
		const totalFuzzRuns = fuzzResults.reduce((sum, f) => sum + f.runs, 0)
		const overallCoverage =
			coverage.length > 0 ? coverage.reduce((sum, c) => sum + c.coverage, 0) / coverage.length : 0

		return {
			totalTests,
			passed,
			failed,
			skipped,
			totalFuzzRuns,
			overallCoverage,
		}
	}

	/**
	 * Generate analysis ID
	 */
	private generateAnalysisId(): string {
		return `foundry-${Date.now()}-${Math.random().toString(36).substring(7)}`
	}
}
