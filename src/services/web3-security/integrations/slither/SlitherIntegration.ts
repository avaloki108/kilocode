// kilocode_change - new file

/**
 * Slither Integration Service
 *
 * This module provides integration with Slither, a static analyzer for Solidity smart contracts.
 * It wraps the Slither CLI and provides a normalized interface for vulnerability detection.
 *
 * @see https://github.com/crytic/slither
 */

import { exec } from "child_process"
import { promisify } from "util"
import path from "path"
import fs from "fs/promises"

const execAsync = promisify(exec)

/**
 * Slither detector configuration
 */
export interface SlitherDetectorConfig {
	enabled: boolean
	checks?: string[] // Specific Slither checks to run
	excludeChecks?: string[] // Checks to exclude
}

/**
 * Slither analysis configuration
 */
export interface SlitherAnalysisConfig {
	contractPath: string
	solcVersion?: string
	optimizations?: boolean
	optimizationRuns?: number
	detectors?: SlitherDetectorConfig[]
	outputFormat?: "json" | "text" | "markdown"
	exclude?: string[] // Files/patterns to exclude
}

/**
 * Slither vulnerability result
 */
export interface SlitherVulnerability {
	check: string
	impact: "high" | "medium" | "low" | "informational"
	confidence: "high" | "medium" | "low"
	description: string
	elements: {
		type: "function" | "contract" | "variable" | "statement"
		name: string
		source_mapping: {
			filename: string
			start: number
			length: number
		}
	}[]
	first_markdown_element: string
}

/**
 * Slither analysis result
 */
export interface SlitherResult {
	success: boolean
	error?: string
	vulnerabilities: SlitherVulnerability[]
	compilationErrors?: string[]
	analysisDuration: number // milliseconds
	slitherVersion: string
}

/**
 * Slither integration service
 */
export class SlitherIntegration {
	private slitherPath: string
	private workingDir: string

	constructor(slitherPath: string = "slither", workingDir: string = process.cwd()) {
		this.slitherPath = slitherPath
		this.workingDir = workingDir
	}

	/**
	 * Check if Slither is installed and available
	 */
	async checkInstallation(): Promise<boolean> {
		try {
			const { stdout } = await execAsync(`${this.slitherPath} --version`)
			return stdout.includes("Slither")
		} catch {
			return false
		}
	}

	/**
	 * Get Slither version
	 */
	async getVersion(): Promise<string> {
		try {
			const { stdout } = await execAsync(`${this.slitherPath} --version`)
			return stdout.trim()
		} catch (error) {
			throw new Error(`Failed to get Slither version: ${error}`)
		}
	}

	/**
	 * Run Slither analysis on a contract
	 */
	async analyze(config: SlitherAnalysisConfig): Promise<SlitherResult> {
		const startTime = Date.now()

		// Validate contract path
		await this.validateContractPath(config.contractPath)

		// Build Slither command
		const command = this.buildSlitherCommand(config)

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
						vulnerabilities: this.normalizeVulnerabilities(result),
						analysisDuration: duration,
						slitherVersion: version,
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
				slitherVersion: version,
			}
		}
	}

	/**
	 * Build Slither command from configuration
	 */
	private buildSlitherCommand(config: SlitherAnalysisConfig): string {
		const parts: string[] = [this.slitherPath]

		// Add contract path
		parts.push(config.contractPath)

		// Add JSON output format if specified
		if (config.outputFormat === "json") {
			parts.push("--json", "-")
		}

		// Add detector configurations
		if (config.detectors) {
			const enabledChecks = config.detectors.filter((d) => d.enabled).flatMap((d) => d.checks || [])
			const disabledChecks = config.detectors.flatMap((d) => d.excludeChecks || [])

			if (enabledChecks.length > 0) {
				parts.push("--detect", enabledChecks.join(","))
			}

			if (disabledChecks.length > 0) {
				parts.push("--exclude", disabledChecks.join(","))
			}
		}

		// Add Solidity compiler version
		if (config.solcVersion) {
			parts.push("--solc-disable-warnings", `--solc-remappings`, `@openzeppelin=node_modules/@openzeppelin`)
		}

		// Add optimization settings
		if (config.optimizations !== undefined) {
			parts.push("--disable-optimizations")
		}

		if (config.optimizationRuns) {
			parts.push("--solc-args", `--optimize --optimize-runs ${config.optimizationRuns}`)
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
	 * Normalize Slither vulnerabilities to standard format
	 */
	private normalizeVulnerabilities(result: any): SlitherVulnerability[] {
		const vulnerabilities: SlitherVulnerability[] = []

		if (!result.results || !result.results.detectors) {
			return vulnerabilities
		}

		for (const detector of result.results.detectors) {
			const check = detector.check
			const description = detector.description
			const impact = this.mapImpact(detector.impact)
			const confidence = this.mapConfidence(detector.confidence)

			for (const element of detector.elements || []) {
				vulnerabilities.push({
					check,
					impact,
					confidence,
					description,
					elements: [
						{
							type: this.mapElementType(element.type),
							name: element.name,
							source_mapping: {
								filename: element.source_mapping.filename,
								start: element.source_mapping.start,
								length: element.source_mapping.length,
							},
						},
					],
					first_markdown_element: detector.first_markdown_element || "",
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Parse vulnerabilities from text output
	 */
	private parseFromTextOutput(output: string, duration: number, version: string): SlitherResult {
		const vulnerabilities: SlitherVulnerability[] = []
		const lines = output.split("\n")
		let currentVulnerability: Partial<SlitherVulnerability> | null = null

		for (const line of lines) {
			// Parse vulnerability header
			const headerMatch = line.match(/^([A-Z_]+)\s+in\s+(.+)$/)
			if (headerMatch) {
				currentVulnerability = {
					check: headerMatch[1],
					description: headerMatch[2],
					impact: "medium",
					confidence: "high",
					elements: [],
				}
				continue
			}

			// Parse impact
			if (line.includes("Impact:")) {
				if (currentVulnerability) {
					const impactMatch = line.match(/Impact:\s+(high|medium|low)/i)
					if (impactMatch) {
						currentVulnerability.impact = impactMatch[1].toLowerCase() as any
					}
				}
			}

			// Parse confidence
			if (line.includes("Confidence:")) {
				if (currentVulnerability) {
					const confidenceMatch = line.match(/Confidence:\s+(high|medium|low)/i)
					if (confidenceMatch) {
						currentVulnerability.confidence = confidenceMatch[1].toLowerCase() as any
					}
				}
			}

			// Parse element location
			const locationMatch = line.match(/^\s+in\s+(.+?)\s+\((\d+)-(\d+)\)$/)
			if (locationMatch && currentVulnerability) {
				currentVulnerability.elements.push({
					type: "function",
					name: locationMatch[1],
					source_mapping: {
						filename: "",
						start: parseInt(locationMatch[2]),
						length: parseInt(locationMatch[3]),
					},
				})
			}

			// End of vulnerability
			if (line.trim() === "" && currentVulnerability) {
				if (currentVulnerability.check && currentVulnerability.description) {
					vulnerabilities.push(currentVulnerability as SlitherVulnerability)
				}
				currentVulnerability = null
			}
		}

		return {
			success: true,
			vulnerabilities,
			analysisDuration: duration,
			slitherVersion: version,
		}
	}

	/**
	 * Map Slither impact to standard format
	 */
	private mapImpact(impact: string): SlitherVulnerability["impact"] {
		const impactLower = impact.toLowerCase()
		if (impactLower === "high") return "high"
		if (impactLower === "medium") return "medium"
		if (impactLower === "low") return "low"
		return "informational"
	}

	/**
	 * Map Slither confidence to standard format
	 */
	private mapConfidence(confidence: string): SlitherVulnerability["confidence"] {
		const confidenceLower = confidence.toLowerCase()
		if (confidenceLower === "high") return "high"
		if (confidenceLower === "medium") return "medium"
		return "low"
	}

	/**
	 * Map element type to standard format
	 */
	private mapElementType(type: string): SlitherVulnerability["elements"][0]["type"] {
		const typeLower = type.toLowerCase()
		if (typeLower.includes("function")) return "function"
		if (typeLower.includes("contract")) return "contract"
		if (typeLower.includes("variable")) return "variable"
		return "statement"
	}

	/**
	 * Get available Slither detectors
	 */
	async getAvailableDetectors(): Promise<string[]> {
		try {
			const { stdout } = await execAsync(`${this.slitherPath} --list-detectors`)
			return stdout
				.split("\n")
				.map((line) => line.trim())
				.filter((line) => line.length > 0 && !line.startsWith("Slither"))
		} catch (error) {
			throw new Error(`Failed to get available detectors: ${error}`)
		}
	}

	/**
	 * Analyze multiple contracts in parallel
	 */
	async analyzeMultiple(configs: SlitherAnalysisConfig[]): Promise<SlitherResult[]> {
		const promises = configs.map((config) => this.analyze(config))
		return Promise.all(promises)
	}
}

/**
 * Create a Slither integration instance
 */
export function createSlitherIntegration(slitherPath?: string, workingDir?: string): SlitherIntegration {
	return new SlitherIntegration(slitherPath, workingDir)
}
