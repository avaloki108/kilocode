// kilocode_change - new file

/**
 * FrontRunning Detection Agent
 *
 * This module provides pattern-based detection for front-running vulnerabilities
 * in smart contracts. Front-running occurs when a malicious actor observes a transaction
 * and submits their own transaction with higher gas fees to get their transaction
 * confirmed first.
 *
 * @see https://swcregistry.io/docs/SWC-114
 */

import type {
	Vulnerability,
	VulnerabilityCategory,
	CodeLocation,
} from "../../packages/core-schemas/src/web3-security/vulnerability.js"
import { VulnerabilityDetector, DetectionParams } from "./VulnerabilityDetector.js"

/**
 * FrontRunning detection patterns
 */
enum FrontRunningPattern {
	/**
	 * Detects functions that manipulate state before external calls
	 * that could be influenced by front-running
	 */
	STATE_MANIPULATION_BEFORE_EXTERNAL_CALL = "state_manipulation_before_external_call",

	/**
	 * Detects functions that reveal user balance or sensitive data
	 * in events/logs that could be used for front-running
	 */
	PRIVATE_DATA_LEAKAGE = "private_data_leakage",

	/**
	 * Detects predictable transaction ordering
	 * (e.g., using block.timestamp or block.number)
	 */
	PREDICTABLE_TRANSACTION_ORDERING = "predictable_transaction_ordering",

	/**
	 * Detects lack of proper access control on critical functions
	 */
	INSUFFICIENT_ACCESS_CONTROL_ON_CRITICAL_FUNCTIONS = "insufficient_access_control_on_critical_functions",

	/**
	 * Detects functions that don't use proper reentrancy guards
	 * (e.g., missing checks-effects-interactions pattern)
	 */
	MISSING_REENTRANCY_GUARDS = "missing_reentrancy_guards",
}

/**
 * FrontRunning Detection Agent
 */
export class FrontRunningDetectionAgent extends VulnerabilityDetector {
	readonly detectorId = "front-running"
	readonly detectorName = "FrontRunning Detection Agent"
	readonly supportedCategories: VulnerabilityCategory[] = ["front_running"]
	readonly supportedChains: string[] = [
		"ethereum",
		"bsc",
		"polygon",
		"arbitrum",
		"optimism",
		"avalanche",
		"fantom",
		"moonbeam",
	]

	constructor() {
		super("front-running")
	}

	/**
	 * Detect front-running vulnerabilities in the provided code
	 */
	async detect(params: DetectionParams): Promise<Vulnerability[]> {
		this.validateParams(params)
		const code = params.code
		const vulnerabilities: Vulnerability[] = []

		// Detect state manipulation before external calls
		vulnerabilities.push(...this.detectStateManipulationBeforeExternalCall(code))

		// Detect private data leakage
		vulnerabilities.push(...this.detectPrivateDataLeakage(code))

		// Detect predictable transaction ordering
		vulnerabilities.push(...this.detectPredictableTransactionOrdering(code))

		// Detect insufficient access control on critical functions
		vulnerabilities.push(...this.detectInsufficientAccessControlOnCriticalFunctions(code))

		// Detect missing reentrancy guards
		vulnerabilities.push(...this.detectMissingReentrancyGuards(code))

		return vulnerabilities
	}

	/**
	 * Detect state manipulation before external calls
	 */
	private detectStateManipulationBeforeExternalCall(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []
		const lines = code.split("\n")

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i]

			// Look for state changes before external calls
			const externalCallPattern = /(\.call\s*\([^)]+\s*)\s*(\.call\s*\([^)]+\s*)/gi
			const externalCallMatch = line.match(externalCallPattern)

			if (externalCallMatch) {
				const stateChanges: string[] = []
				let j = i - 1

				// Look for state changes before the external call
				while (j >= 0) {
					const prevLine = lines[j]
					const stateChangePattern =
						/(\w*(balance|totalSupply|allowance|mapping|count|owner|status)\s*=\s*[^,;)]+)/gi
					const stateChangeMatches = prevLine.match(stateChangePattern)

					if (stateChangeMatches) {
						for (const match of stateChangeMatches) {
							stateChanges.push(match[0])
						}
					}

					// Check if we found state changes before external call
					if (stateChanges.length > 0) {
						vulnerabilities.push({
							id: `${this.detectorId}-state-manipulation-${i}`,
							source: this.detectorId,
							severity: "high",
							category: "front_running",
							title: "State Manipulation Before External Call",
							description:
								"State variables are modified before making an external call. This could allow a front-running attacker to manipulate the contract state by calling the function multiple times with different parameters.",
							locations: [
								{
									file: params.filePath || "unknown",
									line: i + 1,
									column: 0,
									function: externalCallMatch[1],
								},
							],
							metadata: {
								pattern: FrontRunningPattern.STATE_MANIPULATION_BEFORE_EXTERNAL_CALL,
								stateChanges,
							},
						})
					}
				}
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect private data leakage
	 */
	private detectPrivateDataLeakage(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []
		const lines = code.split("\n")

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i]

			// Look for events/logs that emit sensitive data
			const eventPattern = /(event\s+|log\s*\([^)]+\s*)\s*(\.emit\s*\([^)]+\s*)/gi
			const logPattern = /(console\s*\.\s*log\s*\([^)]+\s*)/gi

			const eventMatch = line.match(eventPattern)
			const logMatch = line.match(logPattern)

			if (eventMatch || logMatch) {
				vulnerabilities.push({
					id: `${this.detectorId}-private-leakage-${i}`,
					source: this.detectorId,
					severity: "medium",
					category: "front_running",
					title: "Private Data Leakage",
					description:
						"Sensitive data is emitted through events or logs. This data could be used by front-running attackers to gain an advantage in transaction ordering.",
					locations: [
						{
							file: params.filePath || "unknown",
							line: i + 1,
							column: 0,
							function: eventMatch ? eventMatch[1] : logMatch ? logMatch[1] : "unknown",
						},
					],
					metadata: {
						pattern: FrontRunningPattern.PRIVATE_DATA_LEAKAGE,
					},
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect predictable transaction ordering
	 */
	private detectPredictableTransactionOrdering(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []
		const lines = code.split("\n")

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i]

			// Look for block.timestamp or block.number usage
			const timestampPattern = /block\.timestamp\s*\([^)]+\s*)/gi
			const blockNumberPattern = /block\.number\s*\([^)]+\s*)/gi

			const timestampMatch = line.match(timestampPattern)
			const blockNumberMatch = line.match(blockNumberPattern)

			if (timestampMatch || blockNumberMatch) {
				vulnerabilities.push({
					id: `${this.detectorId}-predictable-ordering-${i}`,
					source: this.detectorId,
					severity: "medium",
					category: "front_running",
					title: "Predictable Transaction Ordering",
					description:
						"Transaction ordering is predictable using block.timestamp or block.number. Front-running attackers can use this predictability to submit transactions with higher gas fees.",
					locations: [
						{
							file: params.filePath || "unknown",
							line: i + 1,
							column: 0,
							function: "unknown", // Could be anywhere in the transaction
						},
					],
					metadata: {
						pattern: FrontRunningPattern.PREDICTABLE_TRANSACTION_ORDERING,
						usedPattern: timestampMatch ? "block.timestamp" : "block.number",
					},
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect insufficient access control on critical functions
	 */
	private detectInsufficientAccessControlOnCriticalFunctions(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []
		const lines = code.split("\n")

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i]

			// Look for critical functions without access control
			const criticalFunctionPattern = /function\s+(withdraw|transfer|mint|burn|claim)\s*\([^)]+\s*)\s*{/gi
			const criticalFunctionMatch = line.match(criticalFunctionPattern)

			if (criticalFunctionMatch) {
				const functionName = criticalFunctionMatch[1]

				// Check if function has access control modifiers
				const hasAccessControl = /onlyOwner|onlyAdmin|require|whenNotPaused|guarded\s*by/.test(line)

				if (!hasAccessControl) {
					vulnerabilities.push({
						id: `${this.detectorId}-insufficient-access-control-${i}`,
						source: this.detectorId,
						severity: "high",
						category: "front_running",
						title: "Insufficient Access Control on Critical Function",
						description: `Critical function '${functionName}' lacks proper access control. A front-running attacker could call this function to drain funds or transfer assets.`,
						locations: [
							{
								file: params.filePath || "unknown",
								line: i + 1,
								column: 0,
								function: functionName,
							},
						],
						metadata: {
							pattern: FrontRunningPattern.INSUFFICIENT_ACCESS_CONTROL_ON_CRITICAL_FUNCTIONS,
							functionName,
						},
					})
				}
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect missing reentrancy guards
	 */
	private detectMissingReentrancyGuards(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []
		const lines = code.split("\n")

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i]

			// Look for external calls without checks-effects-interactions pattern
			const callPattern = /(\.call\s*\([^)]+\s*)/gi
			const callMatch = line.match(callPattern)

			if (callMatch) {
				// Check if checks-effects-interactions modifier is present
				const hasChecksEffects = /checks-effects-interactions/gi.test(line)

				if (!hasChecksEffects) {
					vulnerabilities.push({
						id: `${this.detectorId}-missing-reentrancy-guard-${i}`,
						source: this.detectorId,
						severity: "high",
						category: "front_running",
						title: "Missing Reentrancy Guard",
						description:
							"External call without checks-effects-interactions modifier. This could allow reentrancy attacks, which front-running attackers could exploit to manipulate the call stack.",
						locations: [
							{
								file: params.filePath || "unknown",
								line: i + 1,
								column: 0,
								function: callMatch[1],
							},
						],
						metadata: {
							pattern: FrontRunningPattern.MISSING_REENTRANCY_GUARDS,
						},
					})
				}
			}
		}

		return vulnerabilities
	}
}
