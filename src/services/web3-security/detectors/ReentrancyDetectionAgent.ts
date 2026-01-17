// kilocode_change - new file
import type {
	Vulnerability,
	VulnerabilityCategory,
	VulnerabilitySeverity,
	CodeLocation,
	DetectionResult,
	DetectionParams,
} from "@kilocode/core-schemas"

import { VulnerabilityDetector } from "./VulnerabilityDetector.js"

/**
 * ReentrancyDetectionAgent - Specialized detector for reentrancy vulnerabilities
 *
 * This agent detects reentrancy attacks in smart contracts by analyzing:
 * - External calls before state updates
 * - Control flow manipulation
 * - Gas analysis for suspicious patterns
 * - Cross-contract state dependencies
 */
export class ReentrancyDetectionAgent extends VulnerabilityDetector {
	constructor() {
		super(
			"reentrancy-detector",
			"Reentrancy Detection Agent",
			"Specialized detector for reentrancy vulnerabilities",
			["reentrancy"],
			["evm"],
		)
	}

	/**
	 * Detect reentrancy vulnerabilities in the provided contract
	 */
	async detect(params: DetectionParams): Promise<Vulnerability[]> {
		this.validateParams(params)

		const vulnerabilities: Vulnerability[] = []
		const code = params.code

		// Pattern 1: External calls before state updates
		vulnerabilities.push(
			...this.detectExternalCallsBeforeStateUpdate(code),
			...this.detectControlFlowManipulation(code),
			...this.detectGasAnalysis(code),
			...this.detectCrossContractStateDependencies(code),
		)

		return vulnerabilities
	}

	/**
	 * Detect external calls before state updates
	 */
	private detectExternalCallsBeforeStateUpdate(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Pattern: call to external contract followed by state update
		const externalCallPattern = /call\.value\([^;]+)\.call\{[^;]+\}/g

		const matches = code.matchAll(externalCallPattern)
		for (const match of matches) {
			const [fullMatch, contractName, functionName, externalCall, stateUpdate] = match

			// Check if state update happens after external call
			const stateUpdatePattern = /(?:\.call\{[^;]+\}\.value\s*=\s*;\s*)/g

			if (stateUpdatePattern.test(fullMatch)) {
				vulnerabilities.push({
					id: `reentrancy-${vulnerabilities.length + 1}`,
					title: "Reentrancy: External call before state update",
					description: `External call to ${contractName}.${functionName}() followed by state update in ${externalCall}`,
					category: "reentrancy" as VulnerabilityCategory,
					severity: "high" as VulnerabilitySeverity,
					source: "reentrancy-detector",
					locations: [
						{
							file: params.contractPath,
							line: 0, // Would need actual line number
							column: 0,
							function: functionName,
							contract: contractName,
						},
					],
					confidence: 85,
					impact: "Attacker can recursively call the vulnerable function to drain funds",
					exploitScenario:
						"An attacker calls the vulnerable function with a malicious contract. The function makes an external call to the attacker's contract, which then calls back to the victim contract. Due to the state update happening after the external call, the attacker's contract can execute the second call and drain the victim's funds.",
					remediation:
						"Use the checks-effects-interactions pattern or implement a reentrancy guard. Ensure that state changes happen after all external calls and effects are applied atomically.",
					references: [
						"https://docs.soliditylang.org/en/developing-smart-contracts/security-considerations/reentrancy/",
						"https://swcregistry.com/docs/SWaps-Comprehensive-Checks-Audits-Security-Considerations/",
					],
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect control flow manipulation
	 */
	private detectControlFlowManipulation(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Pattern: state variables modified in external calls
		const stateModificationPattern = /(?:\.call\{[^;]+\}\.value\s*=\s*;\s*)\.call\.value\s*=\s*;\s*)/g

		const matches = code.matchAll(stateModificationPattern)
		for (const match of matches) {
			const [fullMatch, contractName, functionName] = match

			vulnerabilities.push({
				id: `reentrancy-control-flow-${vulnerabilities.length + 1}`,
				title: "Reentrancy: Control flow manipulation",
				description: `State variable modified in external call context in ${contractName}.${functionName}()`,
				category: "reentrancy" as VulnerabilityCategory,
				severity: "medium" as VulnerabilitySeverity,
				source: "reentrancy-detector",
				locations: [
					{
						file: params.contractPath,
						line: 0,
						column: 0,
						function: functionName,
						contract: contractName,
					},
				],
				confidence: 70,
				impact: "Attacker can manipulate control flow to bypass security checks",
				exploitScenario:
					"An attacker makes external calls that modify state variables in ways that bypass intended security controls. This can allow the attacker to bypass reentrancy guards or access control mechanisms.",
				remediation:
					"Use immutable state variables or implement proper access control. Ensure that state modifications only happen through authorized functions with proper guards.",
				references: [
					"https://docs.soliditylang.org/en/developing-smart-contracts/security-considerations/reentrancy/",
					"https://swcregistry.com/docs/Swaps-Comprehensive-Checks-Audits-Security-Considerations/",
				],
			})
		}

		return vulnerabilities
	}

	/**
	 * Detect suspicious gas patterns
	 */
	private detectGasAnalysis(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Pattern: low gas operations before external calls
		const lowGasPattern = /(?:\.call\{[^;]+\}\.gas\(\d+\)\s*<\s*;\s*)/g

		const matches = code.matchAll(lowGasPattern)
		for (const match of matches) {
			const [fullMatch, contractName, functionName, gasAmount] = match

			vulnerabilities.push({
				id: `reentrancy-gas-${vulnerabilities.length + 1}`,
				title: "Reentrancy: Low gas before external call",
				description: `Function ${contractName}.${functionName}() has low gas (${gasAmount}) before external call`,
				category: "gas_issue" as VulnerabilityCategory,
				severity: "low" as VulnerabilitySeverity,
				source: "reentrancy-detector",
				locations: [
					{
						file: params.contractPath,
						line: 0,
						column: 0,
						function: functionName,
						contract: contractName,
					},
				],
				confidence: 60,
				impact: "Low gas can indicate potential reentrancy vulnerability as contract may not have enough gas to complete all operations",
				exploitScenario:
					"An attacker exploits the low gas condition to force the contract into a state where it cannot complete all operations, potentially allowing reentrancy.",
				remediation:
					"Ensure sufficient gas is available for all operations, especially those involving external calls. Consider using gas optimization techniques and proper gas estimation.",
				references: [
					"https://docs.soliditylang.org/en/developing-smart-contracts/security-considerations/gas-optimization/",
					"https://consensys.com/blog/gas-optimization/",
				],
			})
		}

		return vulnerabilities
	}

	/**
	 * Detect cross-contract state dependencies
	 */
	private detectCrossContractStateDependencies(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Pattern: multiple contracts calling each other
		// This is a simplified pattern - real analysis would require AST parsing
		const crossContractPattern = /(?:\.call\{[^;]+\})\s*\(\s*\.call\{[^;]+\})/g

		const matches = code.matchAll(crossContractPattern)
		for (const match of matches) {
			const [fullMatch, contract1, contract2] = match

			vulnerabilities.push({
				id: `reentrancy-cross-contract-${vulnerabilities.length + 1}`,
				title: "Reentrancy: Cross-contract state dependency",
				description: `Potential cross-contract state dependency detected between ${contract1} and ${contract2}`,
				category: "reentrancy" as VulnerabilityCategory,
				severity: "medium" as VulnerabilitySeverity,
				source: "reentrancy-detector",
				locations: [
					{
						file: params.contractPath,
						line: 0,
						column: 0,
						function: "unknown",
						contract: "unknown",
					},
				],
				confidence: 50,
				impact: "Cross-contract dependencies can create complex reentrancy scenarios that are difficult to detect and prevent",
				exploitScenario:
					"Multiple contracts call each other, creating a complex state dependency graph. An attacker can exploit this by orchestrating calls in a specific order to manipulate state across contracts.",
				remediation:
					"Minimize cross-contract dependencies. Use design patterns that avoid circular dependencies. Implement proper state management with clear ownership boundaries.",
				references: [
					"https://docs.soliditylang.org/en/developing-smart-contracts/security-considerations/reentrancy/",
					"https://swcregistry.com/docs/Swaps-Comprehensive-Checks-Audits-Security-Considerations/",
				],
			})
		}

		return vulnerabilities
	}
}
