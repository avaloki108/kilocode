// kilocode_change - new file

/**
 * Crytic Integration Service
 *
 * This module provides integration with Crytic, a collection of security analysis tools for Solidity.
 * It wraps Crytic CLI and provides a normalized interface for vulnerability detection.
 *
 * @see https://github.com/crytic/crytic-compile
 */

import { exec } from "child_process"
import { promisify } from "util"
import path from "path"
import fs from "fs/promises"

const execAsync = promisify(exec)

/**
 * Crytic analysis configuration
 */
export interface CryticAnalysisConfig {
	contractPath: string
	solcVersion?: string
	optimizations?: boolean
	optimizationRuns?: number
	outputFormat?: "json" | "text"
	exclude?: string[] // Files/patterns to exclude
	checks?: string[] // Specific checks to run
}

/**
 * Crytic vulnerability result
 */
export interface CryticVulnerability {
	check: string
	severity: "critical" | "high" | "medium" | "low" | "informational"
	description: string
	locations: {
		file: string
		line: number
		column: number
		function?: string
		contract?: string
	}[]
}

/**
 * Crytic analysis result
 */
export interface CryticResult {
	success: boolean
	error?: string
	vulnerabilities: CryticVulnerability[]
	compilationErrors?: string[]
	analysisDuration: number // milliseconds
	cryticVersion: string
}

/**
 * Crytic integration service
 */
export class CryticIntegration {
	private cryticPath: string
	private workingDir: string

	constructor(cryticPath: string = "crytic-compile", workingDir: string = process.cwd()) {
		this.cryticPath = cryticPath
		this.workingDir = workingDir
	}

	/**
	 * Check if Crytic is installed and available
	 */
	async checkInstallation(): Promise<boolean> {
		try {
			const { stdout } = await execAsync(`${this.cryticPath} --version`)
			return stdout.includes("Crytic")
		} catch {
			return false
		}
	}

	/**
	 * Get Crytic version
	 */
	async getVersion(): Promise<string> {
		try {
			const { stdout } = await execAsync(`${this.cryticPath} --version`)
			return stdout.trim()
		} catch (error) {
			throw new Error(`Failed to get Crytic version: ${error}`)
		}
	}

	/**
	 * Run Crytic analysis on a contract
	 */
	async analyze(config: CryticAnalysisConfig): Promise<CryticResult> {
		const startTime = Date.now()

		// Validate contract path
		await this.validateContractPath(config.contractPath)

		// Build Crytic command
		const command = this.buildCryticCommand(config)

		try {
			const { stdout, stderr } = await execAsync(command, {
				cwd: this.workingDir,
				maxBuffer: 10 * 1024 * 1024, // 10MB buffer
			})

			const duration = Date.now() - startTime
			const version = await this.getVersion()

			if (config.outputFormat === "json") {
				try {
					const result = JSON.parse(stdout)
					return {
						success: true,
						...this.normalizeVulnerabilities(result),
						analysisDuration: duration,
						cryticVersion: version,
					}
				} catch (parseError) {
					// If JSON parsing fails, try to parse from stderr
					return this.parseFromTextOutput(stderr, duration, version)
				}
			} else {
				return this.parseFromTextOutput(stdout || stderr, duration, version)
			}
		} catch (error) {
			const duration = Date.now() - startTime
			const version = await this.getVersion().catch(() => "unknown")

			return {
				success: false,
				error: error instanceof Error ? error.message : String(error),
				vulnerabilities: [],
				analysisDuration: duration,
				cryticVersion: version,
			}
		}
	}

	/**
	 * Build Crytic command from configuration
	 */
	private buildCryticCommand(config: CryticAnalysisConfig): string {
		const parts: string[] = [this.cryticPath]

		// Add contract path
		parts.push(config.contractPath)

		// Add output format
		if (config.outputFormat === "json") {
			parts.push("--json-output", "-")
		}

		// Add Solidity compiler version
		if (config.solcVersion) {
			parts.push("--solc-version", config.solcVersion)
		}

		// Add optimization settings
		if (config.optimizations !== undefined) {
			parts.push("--disable-optimizations")
		}

		if (config.optimizationRuns) {
			parts.push("--optimize-runs", config.optimizationRuns.toString())
		}

		// Add specific checks
		if (config.checks && config.checks.length > 0) {
			parts.push("--check", config.checks.join(","))
		}

		// Add exclusions
		if (config.exclude && config.exclude.length > 0) {
			parts.push("--exclude", config.exclude.join(","))
		}

		return parts.join(" ")
	}

	/**
	 * Validate contract path exists
	 */
	private async validateContractPath(contractPath: string): Promise<void> {
		const fullPath = path.resolve(this.workingDir, contractPath)
		try {
			await fs.access(fullPath)
		} catch {
			throw new Error(`Contract file not found: ${fullPath}`)
		}
	}

	/**
	 * Normalize Crytic vulnerabilities to standard format
	 */
	private normalizeVulnerabilities(result: any): Partial<CryticResult> {
		const vulnerabilities: CryticVulnerability[] = []

		if (!result.issues || !Array.isArray(result.issues)) {
			return {
				vulnerabilities: [],
			}
		}

		for (const issue of result.issues) {
			vulnerabilities.push({
				check: issue.check || issue.check_name || "unknown",
				severity: this.mapSeverity(issue.severity),
				description: issue.description || "",
				locations: this.parseLocations(issue),
			})
		}

		return {
			vulnerabilities,
		}
	}

	/**
	 * Parse locations from Crytic issue
	 */
	private parseLocations(issue: any): CryticVulnerability["locations"] {
		const locations: CryticVulnerability["locations"] = []

		if (issue.locations && Array.isArray(issue.locations)) {
			for (const loc of issue.locations) {
				locations.push({
					file: loc.file || loc.filename || "",
					line: loc.line || 0,
					column: loc.column || loc.col || 0,
					function: loc.function || loc.function_name,
					contract: loc.contract || loc.contract_name,
				})
			}
		}

		// Fallback to single location
		if (locations.length === 0 && issue.file) {
			locations.push({
				file: issue.file,
				line: issue.line || 0,
				column: issue.column || 0,
			})
		}

		return locations
	}

	/**
	 * Parse vulnerabilities from text output
	 */
	private parseFromTextOutput(output: string, duration: number, version: string): CryticResult {
		const vulnerabilities: CryticVulnerability[] = []
		const lines = output.split("\n")
		let currentVulnerability: Partial<CryticVulnerability> | null = null

		for (const line of lines) {
			// Parse check header
			const headerMatch = line.match(/^([A-Z_]+)\s+(.+)/)
			if (headerMatch) {
				currentVulnerability = {
					check: headerMatch[1],
					description: headerMatch[2].trim(),
					severity: "medium",
					locations: [],
				}
				continue
			}

			// Parse severity
			if (line.includes("Severity:")) {
				if (currentVulnerability) {
					const severityMatch = line.match(/Severity:\s+(critical|high|medium|low|informational)/i)
					if (severityMatch) {
						currentVulnerability.severity = severityMatch[1].toLowerCase() as any
					}
				}
			}

			// Parse location
			const locationMatch = line.match(/^\s+Location:\s+(.+?):(\d+):(\d+)/)
			if (locationMatch && currentVulnerability) {
				currentVulnerability.locations.push({
					file: locationMatch[1],
					line: parseInt(locationMatch[2]),
					column: parseInt(locationMatch[3]),
				})
			}

			// End of vulnerability
			if (line.trim() === "" && currentVulnerability) {
				if (currentVulnerability.check && currentVulnerability.description) {
					vulnerabilities.push(currentVulnerability as CryticVulnerability)
				}
				currentVulnerability = null
			}
		}

		return {
			success: true,
			vulnerabilities,
			analysisDuration: duration,
			cryticVersion: version,
		}
	}

	/**
	 * Map Crytic severity to standard format
	 */
	private mapSeverity(severity: string): CryticVulnerability["severity"] {
		const severityLower = severity.toLowerCase()
		if (severityLower === "critical") return "critical"
		if (severityLower === "high") return "high"
		if (severityLower === "medium") return "medium"
		if (severityLower === "low") return "low"
		return "informational"
	}

	/**
	 * Get available Crytic checks
	 */
	async getAvailableChecks(): Promise<string[]> {
		try {
			const { stdout } = await execAsync(`${this.cryticPath} --list-checks`)
			return stdout
				.split("\n")
				.map((line) => line.trim())
				.filter((line) => line.length > 0 && !line.startsWith("Crytic"))
		} catch (error) {
			throw new Error(`Failed to get available checks: ${error}`)
		}
	}

	/**
	 * Analyze multiple contracts in parallel
	 */
	async analyzeMultiple(configs: CryticAnalysisConfig[]): Promise<CryticResult[]> {
		const promises = configs.map((config) => this.analyze(config))
		return Promise.all(promises)
	}
}

/**
 * Create a Crytic integration instance
 */
export function createCryticIntegration(cryticPath?: string, workingDir?: string): CryticIntegration {
	return new CryticIntegration(cryticPath, workingDir)
}
