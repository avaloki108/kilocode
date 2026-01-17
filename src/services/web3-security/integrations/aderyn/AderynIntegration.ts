// kilocode_change - new file

/**
 * Aderyn Integration Service
 *
 * This module provides integration with Aderyn, a Rust-based static analyzer for Solidity smart contracts.
 * It wraps Aderyn CLI and provides a normalized interface for vulnerability detection.
 *
 * @see https://github.com/Certora/Aderyn
 */

import { exec } from "child_process"
import { promisify } from "util"
import path from "path"
import fs from "fs/promises"

const execAsync = promisify(exec)

/**
 * Aderyn detector configuration
 */
export interface AderynDetectorConfig {
	enabled: boolean
	severity?: "low" | "medium" | "high" | "critical"
}

/**
 * Aderyn analysis configuration
 */
export interface AderynAnalysisConfig {
	contractPath: string
	solcVersion?: string
	outputFormat?: "json" | "sarif" | "text"
	exclude?: string[] // Files/patterns to exclude
	standard?: string // Solidity standard version
}

/**
 * Aderyn vulnerability result
 */
export interface AderynVulnerability {
	detectorId: string
	detectorName: string
	severity: "critical" | "high" | "medium" | "low" | "informational"
	description: string
	locations: {
		file: string
		line: number
		column: number
		function?: string
		contract?: string
	}[]
	metadata?: {
		[key: string]: any
	}
}

/**
 * Aderyn analysis result
 */
export interface AderynResult {
	success: boolean
	error?: string
	vulnerabilities: AderynVulnerability[]
	compilationErrors?: string[]
	analysisDuration: number // milliseconds
	aderynVersion: string
	totalDetectorsRun: number
}

/**
 * Aderyn integration service
 */
export class AderynIntegration {
	private aderynPath: string
	private workingDir: string

	constructor(aderynPath: string = "aderyn", workingDir: string = process.cwd()) {
		this.aderynPath = aderynPath
		this.workingDir = workingDir
	}

	/**
	 * Check if Aderyn is installed and available
	 */
	async checkInstallation(): Promise<boolean> {
		try {
			const { stdout } = await execAsync(`${this.aderynPath} --version`)
			return stdout.includes("aderyn")
		} catch {
			return false
		}
	}

	/**
	 * Get Aderyn version
	 */
	async getVersion(): Promise<string> {
		try {
			const { stdout } = await execAsync(`${this.aderynPath} --version`)
			return stdout.trim()
		} catch (error) {
			throw new Error(`Failed to get Aderyn version: ${error}`)
		}
	}

	/**
	 * Run Aderyn analysis on a contract
	 */
	async analyze(config: AderynAnalysisConfig): Promise<AderynResult> {
		const startTime = Date.now()

		// Validate contract path
		await this.validateContractPath(config.contractPath)

		// Build Aderyn command
		const command = this.buildAderynCommand(config)

		try {
			const { stdout, stderr } = await execAsync(command, {
				cwd: this.workingDir,
				maxBuffer: 10 * 1024 * 1024, // 10MB buffer
			})

			const duration = Date.now() - startTime
			const version = await this.getVersion()

			if (config.outputFormat === "json" || config.outputFormat === "sarif") {
				try {
					const result = JSON.parse(stdout)
					return {
						success: true,
						...this.normalizeVulnerabilities(result),
						analysisDuration: duration,
						aderynVersion: version,
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
				aderynVersion: version,
			}
		}
	}

	/**
	 * Build Aderyn command from configuration
	 */
	private buildAderynCommand(config: AderynAnalysisConfig): string {
		const parts: string[] = [this.aderynPath]

		// Add contract path
		parts.push(config.contractPath)

		// Add output format
		if (config.outputFormat) {
			parts.push("--output", config.outputFormat)
		}

		// Add Solidity compiler version
		if (config.solcVersion) {
			parts.push("--solc-version", config.solcVersion)
		}

		// Add Solidity standard
		if (config.standard) {
			parts.push("--standard", config.standard)
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
	 * Normalize Aderyn vulnerabilities to standard format
	 */
	private normalizeVulnerabilities(result: any): Partial<AderynResult> {
		const vulnerabilities: AderynVulnerability[] = []

		if (!result.issues || !Array.isArray(result.issues)) {
			return {
				vulnerabilities: [],
				totalDetectorsRun: result.totalDetectors || 0,
			}
		}

		for (const issue of result.issues) {
			vulnerabilities.push({
				detectorId: issue.detectorId || issue.detector_id || "unknown",
				detectorName: issue.detectorName || issue.detector_name || "Unknown",
				severity: this.mapSeverity(issue.severity),
				description: issue.description || "",
				locations: this.parseLocations(issue),
				metadata: issue.metadata || {},
			})
		}

		return {
			vulnerabilities,
			totalDetectorsRun: result.totalDetectors || vulnerabilities.length,
		}
	}

	/**
	 * Parse locations from Aderyn issue
	 */
	private parseLocations(issue: any): AderynVulnerability["locations"] {
		const locations: AderynVulnerability["locations"] = []

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
	private parseFromTextOutput(output: string, duration: number, version: string): AderynResult {
		const vulnerabilities: AderynVulnerability[] = []
		const lines = output.split("\n")
		let currentVulnerability: Partial<AderynVulnerability> | null = null

		for (const line of lines) {
			// Parse detector header
			const headerMatch = line.match(/^\[(.+?)\]\s+(.+)/)
			if (headerMatch) {
				currentVulnerability = {
					detectorId: headerMatch[1],
					detectorName: headerMatch[2].trim(),
					severity: "medium",
					description: "",
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
				if (currentVulnerability.detectorId && currentVulnerability.detectorName) {
					vulnerabilities.push(currentVulnerability as AderynVulnerability)
				}
				currentVulnerability = null
			}
		}

		return {
			success: true,
			vulnerabilities,
			analysisDuration: duration,
			aderynVersion: version,
			totalDetectorsRun: vulnerabilities.length,
		}
	}

	/**
	 * Map Aderyn severity to standard format
	 */
	private mapSeverity(severity: string): AderynVulnerability["severity"] {
		const severityLower = severity.toLowerCase()
		if (severityLower === "critical") return "critical"
		if (severityLower === "high") return "high"
		if (severityLower === "medium") return "medium"
		if (severityLower === "low") return "low"
		return "informational"
	}

	/**
	 * Get available Aderyn detectors
	 */
	async getAvailableDetectors(): Promise<string[]> {
		try {
			const { stdout } = await execAsync(`${this.aderynPath} --list`)
			return stdout
				.split("\n")
				.map((line) => line.trim())
				.filter((line) => line.length > 0 && !line.startsWith("Aderyn"))
		} catch (error) {
			throw new Error(`Failed to get available detectors: ${error}`)
		}
	}

	/**
	 * Analyze multiple contracts in parallel
	 */
	async analyzeMultiple(configs: AderynAnalysisConfig[]): Promise<AderynResult[]> {
		const promises = configs.map((config) => this.analyze(config))
		return Promise.all(promises)
	}
}

/**
 * Create an Aderyn integration instance
 */
export function createAderynIntegration(aderynPath?: string, workingDir?: string): AderynIntegration {
	return new AderynIntegration(aderynPath, workingDir)
}
