// kilocode_change - new file

/**
 * Mythril Integration Service
 *
 * This module provides integration with Mythril, a symbolic execution tool for Ethereum smart contracts.
 * It wraps the Mythril CLI and provides a normalized interface for vulnerability detection.
 *
 * @see https://github.com/ConsenSys/mythril
 */

import { exec } from "child_process"
import { promisify } from "util"
import path from "path"
import fs from "fs/promises"

const execAsync = promisify(exec)

/**
 * Mythril analysis configuration
 */
export interface MythrilAnalysisConfig {
	contractPath: string
	contractAddress?: string // For analyzing deployed contracts
	rpcUrl?: string // Ethereum RPC endpoint
	maxDepth?: number // Maximum execution depth
	timeout?: number // Analysis timeout in seconds
	strategy?: "bfs" | "dfs" | "naive-random" | "weighted-random"
	solverTimeout?: number // SMT solver timeout in milliseconds
	createTxGas?: number // Gas limit for transaction creation modules
}

/**
 * Mythril vulnerability result
 */
export interface MythrilVulnerability {
	swcId: string // SWC ID (e.g., SWC-107)
	swcTitle: string
	description: string
	severity: "high" | "medium" | "low"
	locations: {
		functionName: string
		address?: string
		pc?: number // Program counter
	}[]
	firstSeenBlock?: number
}

/**
 * Mythril analysis result
 */
export interface MythrilResult {
	success: boolean
	error?: string
	vulnerabilities: MythrilVulnerability[]
	analysisDuration: number // milliseconds
	mythrilVersion: string
	totalStatesExplored?: number
}

/**
 * Mythril integration service
 */
export class MythrilIntegration {
	private mythrilPath: string
	private workingDir: string

	constructor(mythrilPath: string = "mythril", workingDir: string = process.cwd()) {
		this.mythrilPath = mythrilPath
		this.workingDir = workingDir
	}

	/**
	 * Check if Mythril is installed and available
	 */
	async checkInstallation(): Promise<boolean> {
		try {
			const { stdout } = await execAsync(`${this.mythrilPath} version`)
			return stdout.includes("Mythril")
		} catch {
			return false
		}
	}

	/**
	 * Get Mythril version
	 */
	async getVersion(): Promise<string> {
		try {
			const { stdout } = await execAsync(`${this.mythrilPath} version`)
			return stdout.trim()
		} catch (error) {
			throw new Error(`Failed to get Mythril version: ${error}`)
		}
	}

	/**
	 * Analyze a smart contract using Mythril
	 */
	async analyze(config: MythrilAnalysisConfig): Promise<MythrilResult> {
		const startTime = Date.now()

		// Validate configuration
		await this.validateConfig(config)

		// Build Mythril command
		const command = this.buildMythrilCommand(config)

		try {
			const { stdout, stderr } = await execAsync(command, {
				cwd: this.workingDir,
				maxBuffer: 10 * 1024 * 1024, // 10MB buffer
				timeout: config.timeout ? config.timeout * 1000 : undefined,
			})

			const duration = Date.now() - startTime
			const version = await this.getVersion()

			return this.parseMythrilOutput(stdout || stderr, duration, version)
		} catch (error) {
			const duration = Date.now() - startTime
			const version = await this.getVersion().catch(() => "unknown")

			return {
				success: false,
				error: error instanceof Error ? error.message : String(error),
				vulnerabilities: [],
				analysisDuration: duration,
				mythrilVersion: version,
			}
		}
	}

	/**
	 * Build Mythril command from configuration
	 */
	private buildMythrilCommand(config: MythrilAnalysisConfig): string {
		const parts: string[] = [this.mythrilPath, "analyze"]

		// Add contract path or address
		if (config.contractAddress) {
			parts.push("-a", config.contractAddress)
		} else {
			parts.push(config.contractPath)
		}

		// Add RPC URL
		if (config.rpcUrl) {
			parts.push("--rpc", config.rpcUrl)
		}

		// Add execution depth
		if (config.maxDepth) {
			parts.push("--max-depth", config.maxDepth.toString())
		}

		// Add search strategy
		if (config.strategy) {
			parts.push("--solv", config.strategy)
		}

		// Add solver timeout
		if (config.solverTimeout) {
			parts.push("--smt-timeout", config.solverTimeout.toString())
		}

		// Add transaction gas limit
		if (config.createTxGas) {
			parts.push("--create-tx-gas", config.createTxGas.toString())
		}

		// Enable output for vulnerabilities
		parts.push("--solv", "json")

		return parts.join(" ")
	}

	/**
	 * Validate configuration
	 */
	private async validateConfig(config: MythrilAnalysisConfig): Promise<void> {
		// Either contract path or address must be provided
		if (!config.contractPath && !config.contractAddress) {
			throw new Error("Either contractPath or contractAddress must be provided")
		}

		// If contract path is provided, validate it exists
		if (config.contractPath) {
			const fullPath = path.resolve(this.workingDir, config.contractPath)
			try {
				await fs.access(fullPath)
			} catch {
				throw new Error(`Contract file not found: ${fullPath}`)
			}
		}

		// If analyzing deployed contract, RPC URL is required
		if (config.contractAddress && !config.rpcUrl) {
			throw new Error("RPC URL is required when analyzing deployed contracts")
		}
	}

	/**
	 * Parse Mythril output
	 */
	private parseMythrilOutput(output: string, duration: number, version: string): MythrilResult {
		try {
			const data = JSON.parse(output)

			if (!data.issues || !Array.isArray(data.issues)) {
				return {
					success: true,
					vulnerabilities: [],
					analysisDuration: duration,
					mythrilVersion: version,
				}
			}

			const vulnerabilities: MythrilVulnerability[] = data.issues.map((issue: any) => ({
				swcId: issue.swcID || issue.swc_id || "unknown",
				swcTitle: issue.swcTitle || issue.swc_title || "Unknown",
				description: issue.description || "",
				severity: this.mapSeverity(issue.severity),
				locations: this.parseLocations(issue),
				firstSeenBlock: issue.firstSeenBlock,
			}))

			return {
				success: true,
				vulnerabilities,
				analysisDuration: duration,
				mythrilVersion: version,
				totalStatesExplored: data.totalStates,
			}
		} catch (parseError) {
			// If JSON parsing fails, try to parse from text output
			return this.parseFromTextOutput(output, duration, version)
		}
	}

	/**
	 * Parse locations from Mythril issue
	 */
	private parseLocations(issue: any): MythrilVulnerability["locations"] {
		const locations: MythrilVulnerability["locations"] = []

		if (issue.address) {
			locations.push({
				functionName: issue.function || "unknown",
				address: issue.address,
				pc: issue.pc,
			})
		}

		if (issue.locations && Array.isArray(issue.locations)) {
			for (const loc of issue.locations) {
				locations.push({
					functionName: loc.function || loc.function_name || "unknown",
					address: loc.address,
					pc: loc.pc,
				})
			}
		}

		return locations
	}

	/**
	 * Parse vulnerabilities from text output
	 */
	private parseFromTextOutput(output: string, duration: number, version: string): MythrilResult {
		const vulnerabilities: MythrilVulnerability[] = []
		const lines = output.split("\n")
		let currentVulnerability: Partial<MythrilVulnerability> | null = null

		for (const line of lines) {
			// Parse SWC ID
			const swcMatch = line.match(/SWC-(\d+):\s*(.+)/)
			if (swcMatch) {
				currentVulnerability = {
					swcId: `SWC-${swcMatch[1]}`,
					swcTitle: swcMatch[2].trim(),
					severity: "medium",
					description: "",
					locations: [],
				}
				continue
			}

			// Parse severity
			if (line.includes("Severity:")) {
				if (currentVulnerability) {
					const severityMatch = line.match(/Severity:\s+(high|medium|low)/i)
					if (severityMatch) {
						currentVulnerability.severity = severityMatch[1].toLowerCase() as any
					}
				}
			}

			// Parse function name
			const functionMatch = line.match(/Function:\s*(.+)/)
			if (functionMatch && currentVulnerability) {
				currentVulnerability.locations.push({
					functionName: functionMatch[1].trim(),
				})
			}

			// Parse address
			const addressMatch = line.match(/Address:\s*(0x[a-fA-F0-9]+)/)
			if (addressMatch && currentVulnerability) {
				const lastLocation = currentVulnerability.locations[currentVulnerability.locations.length - 1]
				if (lastLocation) {
					lastLocation.address = addressMatch[1]
				}
			}

			// End of vulnerability
			if (line.trim() === "" && currentVulnerability) {
				if (currentVulnerability.swcId) {
					vulnerabilities.push(currentVulnerability as MythrilVulnerability)
				}
				currentVulnerability = null
			}
		}

		return {
			success: true,
			vulnerabilities,
			analysisDuration: duration,
			mythrilVersion: version,
		}
	}

	/**
	 * Map Mythril severity to standard format
	 */
	private mapSeverity(severity: string): MythrilVulnerability["severity"] {
		const severityLower = severity.toLowerCase()
		if (severityLower === "high") return "high"
		if (severityLower === "medium") return "medium"
		return "low"
	}

	/**
	 * Analyze a deployed contract on Ethereum
	 */
	async analyzeDeployedContract(
		contractAddress: string,
		rpcUrl: string,
		config?: Partial<MythrilAnalysisConfig>,
	): Promise<MythrilResult> {
		return this.analyze({
			contractAddress,
			rpcUrl,
			...config,
		})
	}

	/**
	 * List available Mythril modules
	 */
	async getAvailableModules(): Promise<string[]> {
		try {
			const { stdout } = await execAsync(`${this.mythrilPath} list`)
			return stdout
				.split("\n")
				.map((line) => line.trim())
				.filter((line) => line.length > 0 && !line.startsWith("Mythril"))
		} catch (error) {
			throw new Error(`Failed to get available modules: ${error}`)
		}
	}

	/**
	 * Analyze multiple contracts in parallel
	 */
	async analyzeMultiple(configs: MythrilAnalysisConfig[]): Promise<MythrilResult[]> {
		const promises = configs.map((config) => this.analyze(config))
		return Promise.all(promises)
	}
}

/**
 * Create a Mythril integration instance
 */
export function createMythrilIntegration(mythrilPath?: string, workingDir?: string): MythrilIntegration {
	return new MythrilIntegration(mythrilPath, workingDir)
}
