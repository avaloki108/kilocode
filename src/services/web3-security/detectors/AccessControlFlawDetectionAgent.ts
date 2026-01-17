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
 * AccessControlFlawDetectionAgent - Specialized detector for access control flaws
 *
 * This agent detects access control vulnerabilities in smart contracts
 * by analyzing:
 * - Function visibility modifiers
 * - Role-based access control
 * - Delegatecall patterns
 * - tx.origin vs msg.sender usage
 * - Ownership and transfer restrictions
 */
export class AccessControlFlawDetectionAgent extends VulnerabilityDetector {
	constructor() {
		super(
			"access-control-detector",
			"Access Control Flaw Detection Agent",
			"Specialized detector for access control vulnerabilities",
			["access_control"],
			["evm"],
		)
	}

	/**
	 * Detect access control vulnerabilities in the provided contract
	 */
	async detect(params: DetectionParams): Promise<Vulnerability[]> {
		this.validateParams(params)

		const vulnerabilities: Vulnerability[] = []
		const code = params.code

		// Pattern 1: Public function without access control
		vulnerabilities.push(...this.detectPublicFunctions(code))

		// Pattern 2: Missing onlyOwner modifier
		vulnerabilities.push(...this.detectMissingOnlyOwnerModifier(code))

		// Pattern 3: Incorrect use of onlyAdmin modifier
		vulnerabilities.push(...this.detectIncorrectOnlyAdminModifier(code))

		// Pattern 4: Incorrect use of tx.origin
		vulnerabilities.push(...this.detectIncorrectTxOriginUsage(code))

		// Pattern 5: Delegatecall without access control
		vulnerabilities.push(...this.detectDelegatecallWithoutAccessControl(code))

		// Pattern 6: Missing access control on critical functions
		vulnerabilities.push(...this.detectMissingAccessControl(code))

		// Pattern 7: Incorrect ownership checks
		vulnerabilities.push(...this.detectIncorrectOwnershipChecks(code))

		// Pattern 8: Weak transfer restrictions
		vulnerabilities.push(...this.detectWeakTransferRestrictions(code))

		// Pattern 9: Hardcoded addresses in logic
		vulnerabilities.push(...this.detectHardcodedAddresses(code))

		return vulnerabilities
	}

	/**
	 * Detect public functions without access control
	 */
	private detectPublicFunctions(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Pattern: functions without visibility modifiers
		const publicFunctionPattern =
			/function\s+([a-zA-Z_$][a-zA-Z0-9]*)\s*(?:\s*public|viewable|external|pure)\s*\([^;]*?)\s*\)/g

		const matches = code.matchAll(publicFunctionPattern)
		for (const match of matches) {
			const [fullMatch, functionName, modifiers] = match

			// Check if function is public without proper access control
			if (!modifiers.includes("public")) {
				vulnerabilities.push({
					id: `access-control-public-function-${vulnerabilities.length + 1}`,
					title: "Access Control: Public function without access control",
					description: `Function ${functionName}() is public but lacks access control modifiers`,
					category: "access_control" as VulnerabilityCategory,
					severity: "high" as VulnerabilitySeverity,
					source: "access-control-detector",
					locations: [
						{
							file: params.contractPath,
							line: 0,
							column: 0,
							function: functionName,
							contract: params.contractName || "Unknown",
						},
					],
					confidence: 85,
					impact: "Public functions without access control can be called by anyone, potentially allowing unauthorized state changes or fund transfers",
					exploitScenario:
						"An attacker can call a public function directly to manipulate contract state, transfer funds, or perform unauthorized actions.",
					remediation:
						"Use appropriate visibility modifiers (private, internal) for functions that should not be publicly accessible. Implement access control checks.",
					references: [
						"https://docs.soliditylang.org/en/developing-smart-contracts/security-considerations/access-control/",
						"https://swcregistry.com/docs/Swaps-Comprehensive-Checks-Audits-Security-Considerations/",
					],
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect missing onlyOwner modifier
	 */
	private detectMissingOnlyOwnerModifier(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Pattern: onlyOwner modifier without other access control
		const onlyOwnerPattern =
			/function\s+([a-zA-Z_$][a-zA-Z0-9]*)\s*(?:\s*public|viewable|external|pure)\s*\([^;]*?)\s*onlyOwner\([^;]*?)\s*\)/g

		const matches = code.matchAll(onlyOwnerPattern)
		for (const match of matches) {
			const [fullMatch, functionName, modifiers] = match

			// Check if onlyOwner is used without other access control
			if (modifiers.length === 1 && modifiers.includes("onlyOwner")) {
				vulnerabilities.push({
					id: `access-control-only-owner-${vulnerabilities.length + 1}`,
					title: "Access Control: Missing onlyOwner modifier",
					description: `Function ${functionName}() uses onlyOwner modifier without proper access control`,
					category: "access_control" as VulnerabilityCategory,
					severity: "medium" as VulnerabilitySeverity,
					source: "access-control-detector",
					locations: [
						{
							file: params.contractPath,
							line: 0,
							column: 0,
							function: functionName,
							contract: params.contractName || "Unknown",
						},
					],
					confidence: 75,
					impact: "The onlyOwner modifier restricts function access to only the contract owner, but this can be bypassed through delegatecall or other mechanisms",
					exploitScenario:
						"An attacker can use delegatecall to bypass the onlyOwner restriction and call the function as if they were the owner, potentially gaining unauthorized access.",
					remediation:
						"Use onlyOwner in combination with other access control mechanisms like Ownable or implement proper ownership transfer logic. Consider using OpenZeppelin's Ownable pattern.",
					references: [
						"https://docs.soliditylang.org/en/developing-smart-contracts/access-control/",
						"https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable.sol",
						"https://blog.openzeppelin.com/understanding-the-different-roles-in-openzeppelin/",
					],
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect incorrect use of onlyAdmin modifier
	 */
	private detectIncorrectOnlyAdminModifier(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Pattern: onlyAdmin modifier without proper access control
		const onlyAdminPattern =
			/function\s+([a-zA-Z_$][a-zA-Z0-9]*)\s*(?:\s*public|viewable|external|pure)\s*\([^;]*?)\s*onlyAdmin\([^;]*?)\s*\)/g

		const matches = code.matchAll(onlyAdminPattern)
		for (const match of matches) {
			const [fullMatch, functionName, modifiers] = match

			// Check if onlyAdmin is used without other access control
			if (modifiers.length === 1 && modifiers.includes("onlyAdmin")) {
				vulnerabilities.push({
					id: `access-control-only-admin-${vulnerabilities.length + 1}`,
					title: "Access Control: Incorrect use of onlyAdmin modifier",
					description: `Function ${functionName}() uses onlyAdmin modifier without proper access control`,
					category: "access_control" as VulnerabilityCategory,
					severity: "medium" as VulnerabilitySeverity,
					source: "access-control-detector",
					locations: [
						{
							file: params.contractPath,
							line: 0,
							column: 0,
							function: functionName,
							contract: params.contractName || "Unknown",
						},
					],
					confidence: 75,
					impact: "The onlyAdmin modifier restricts function access to only the contract admin, but this can be bypassed through delegatecall or compromised keys.",
					exploitScenario:
						"An attacker can use delegatecall to bypass the onlyAdmin restriction and call the function as if they were the admin, potentially gaining unauthorized control.",
					remediation:
						"Use onlyAdmin in combination with other access control mechanisms like Ownable or implement proper admin access control. Consider using OpenZeppelin's AccessControl pattern.",
					references: [
						"https://docs.soliditylang.org/en/developing-smart-contracts/access-control/",
						"https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/AccessControl.sol",
						"https://blog.openzeppelin.com/understanding-the-different-roles-in-openzeppelin/",
					],
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect incorrect use of tx.origin
	 */
	private detectIncorrectTxOriginUsage(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Pattern: tx.origin used in authorization
		const txOriginPattern = /(?:msg\.sender|tx\.origin)\s*\)/g

		const matches = code.matchAll(txOriginPattern)
		for (const match of matches) {
			const [fullMatch, variable, usage] = match

			// Check if tx.origin is used for authorization
			if (usage.includes("tx.origin")) {
				vulnerabilities.push({
					id: `access-control-tx-origin-authorization-${vulnerabilities.length + 1}`,
					title: "Access Control: Incorrect tx.origin usage",
					description: `tx.origin used for authorization in ${variable}`,
					category: "access_control" as VulnerabilityCategory,
					severity: "high" as VulnerabilitySeverity,
					source: "access-control-detector",
					locations: [
						{
							file: params.contractPath,
							line: 0,
							column: 0,
							function: "unknown",
							contract: params.contractName || "Unknown",
						},
					],
					confidence: 85,
					impact: "tx.origin should only be used for authentication, not authorization. Using tx.origin for authorization can allow attackers to bypass access controls by spoofing the original caller.",
					exploitScenario:
						"An attacker exploits the use of tx.origin for authorization by calling the function from a malicious contract that uses tx.origin for access control. The malicious contract can then approve the call as if it came from tx.origin, bypassing the intended access controls.",
					remediation:
						"Use msg.sender for authorization instead of tx.origin. Implement proper access control checks that verify the caller's identity through msg.sender rather than tx.origin.",
					references: [
						"https://docs.soliditylang.org/en/developing-smart-contracts/security-considerations/",
						"https://consensys.com/blog/tx-origin-wrong/",
						"https://swcregistry.com/docs/Swaps-Comprehensive-Checks-Audits-Security-Considerations/",
					],
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect delegatecall without access control
	 */
	private detectDelegatecallWithoutAccessControl(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Pattern: delegatecall to arbitrary address
		const delegatecallPattern = /(?:\s*delegatecall\([^;]+\)\s*\([^;]*?)\s*\)/g

		const matches = code.matchAll(delegatecallPattern)
		for (const match of matches) {
			const [fullMatch, targetAddress] = match

			// Check if delegatecall is used without proper access control
			if (targetAddress !== "address(this)") {
				vulnerabilities.push({
					id: `access-control-delegatecall-no-access-control-${vulnerabilities.length + 1}`,
					title: "Access Control: Delegatecall without access control",
					description: `Delegatecall to ${targetAddress} without proper access control`,
					category: "access_control" as VulnerabilityCategory,
					severity: "high" as VulnerabilitySeverity,
					source: "access-control-detector",
					locations: [
						{
							file: params.contractPath,
							line: 0,
							column: 0,
							function: "unknown",
							contract: params.contractName || "Unknown",
						},
					],
					confidence: 85,
					impact: "Delegatecall to arbitrary addresses without access control can allow attackers to transfer ownership or call functions on user-controlled contracts",
					exploitScenario:
						"An attacker uses delegatecall to transfer ownership or call functions on a user-controlled contract by calling it from a malicious contract. This can allow the attacker to bypass access controls and manipulate the contract state.",
					remediation:
						"Use delegatecall with access control. Ensure that delegatecall targets have proper access control or use patterns like Ownable to verify ownership transfers.",
					references: [
						"https://docs.soliditylang.org/en/developing-smart-contracts/security-considerations/",
						"https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/proxy/Ownable.sol",
						"https://blog.openzeppelin.com/understanding-the-different-roles-in-openzeppelin/",
					],
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect missing access control on critical functions
	 */
	private detectMissingAccessControl(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Pattern: critical functions without access control
		const criticalFunctionPattern =
			/(?:function\s+(?:transfer|mint|burn|withdraw|kill|selfdestruct|pause|unpause|upgrade|addAdmin|setOwner)\s*\([^;]*?)\s*\)/g

		const matches = code.matchAll(criticalFunctionPattern)
		for (const match of matches) {
			const [fullMatch, functionName] = match

			// Check if critical function lacks access control
			if (!this.hasAccessControlModifier(functionName)) {
				vulnerabilities.push({
					id: `access-control-missing-control-${vulnerabilities.length + 1}`,
					title: "Access Control: Missing access control on critical function",
					description: `Critical function ${functionName}() lacks proper access control`,
					category: "access_control" as VulnerabilityCategory,
					severity: "critical" as VulnerabilitySeverity,
					source: "access-control-detector",
					locations: [
						{
							file: params.contractPath,
							line: 0,
							column: 0,
							function: functionName,
							contract: params.contractName || "Unknown",
						},
					],
					confidence: 90,
					impact: "Critical functions without access control can be exploited to drain funds, transfer ownership, or cause denial of service. Attackers can call these functions directly to perform unauthorized actions.",
					exploitScenario:
						"An attacker can call critical functions like transfer, withdraw, or selfdestruct without proper access control, potentially draining funds or taking ownership of the contract.",
					remediation:
						"Always use access control modifiers (onlyOwner, onlyAdmin) on critical functions. Implement proper ownership checks. Consider using OpenZeppelin's AccessControl pattern.",
					references: [
						"https://docs.soliditylang.org/en/developing-smart-contracts/security-considerations/access-control/",
						"https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/AccessControl.sol",
						"https://swcregistry.com/docs/Swaps-Comprehensive-Checks-Audits-Security-Considerations/",
					],
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect incorrect ownership checks
	 */
	private detectIncorrectOwnershipChecks(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Pattern: weak ownership checks
		const weakOwnershipPattern = /(?:owner\s*=\s*address\(this\)|msg\.sender)\s*\)/g

		const matches = code.matchAll(weakOwnershipPattern)
		for (const match of matches) {
			const [fullMatch, checkType] = match

			vulnerabilities.push({
				id: `access-control-weak-ownership-${vulnerabilities.length + 1}`,
				title: "Access Control: Incorrect ownership check",
				description: `Weak ownership check: ${checkType}`,
				category: "access_control" as VulnerabilityCategory,
				severity: "medium" as VulnerabilitySeverity,
				source: "access-control-detector",
				locations: [
					{
						file: params.contractPath,
						line: 0,
						column: 0,
						function: "unknown",
						contract: params.contractName || "Unknown",
					},
				],
				confidence: 75,
				impact: "Weak ownership checks can be bypassed by attackers using delegatecall or other mechanisms",
				exploitScenario:
					"An attacker can exploit weak ownership checks to gain unauthorized access or transfer ownership. For example, if the check is `owner == msg.sender`, an attacker can use delegatecall to make themselves the owner.",
				remediation:
					"Use proper ownership patterns like Ownable or implement rigorous ownership verification. Consider using OpenZeppelin's Ownable pattern.",
				references: [
					"https://docs.soliditylang.org/en/developing-smart-contracts/access-control/",
					"https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/proxy/Ownable.sol",
					"https://blog.openzeppelin.com/understanding-the-different-roles-in-openzeppelin/",
				],
			})
		}

		return vulnerabilities
	}

	/**
	 * Detect weak transfer restrictions
	 */
	private detectWeakTransferRestrictions(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Pattern: weak transfer restrictions
		const weakTransferPattern = /(?:require\s*\(\s*address\(this\)|msg\.sender)\s*!=\s*address\(0\))\s*\)/g

		const matches = code.matchAll(weakTransferPattern)
		for (const match of matches) {
			const [fullMatch, restriction] = match

			vulnerabilities.push({
				id: `access-control-weak-transfer-${vulnerabilities.length + 1}`,
				title: "Access Control: Weak transfer restriction",
				description: `Weak transfer restriction: ${restriction}`,
				category: "access_control" as VulnerabilityCategory,
				severity: "medium" as VulnerabilitySeverity,
				source: "access-control-detector",
				locations: [
					{
						file: params.contractPath,
						line: 0,
						column: 0,
						function: "unknown",
						contract: params.contractName || "Unknown",
					},
				],
				confidence: 75,
				impact: "Weak transfer restrictions can be exploited to prevent legitimate users from transferring tokens or to create denial of service scenarios",
				exploitScenario:
					"An attacker can exploit weak transfer restrictions to prevent legitimate token transfers or create denial of service. For example, if the restriction is `require(msg.sender == address(0))`, an attacker can front-run a transaction to become the first sender and block legitimate transfers.",
				remediation:
					"Use proper transfer patterns. Consider using OpenZeppelin's transfer patterns or implementing proper access control for token transfers.",
				references: [
					"https://docs.soliditylang.org/en/developing-smart-contracts/security-considerations/",
					"https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/ERC20.sol",
					"https://consensys.com/blog/weak-transfer-security/",
				],
			})
		}

		return vulnerabilities
	}

	/**
	 * Detect hardcoded addresses in logic
	 */
	private detectHardcodedAddresses(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Pattern: hardcoded addresses
		const hardcodedAddressPattern = /(?:0x[a-fA-F0-9]{40}\s*|address\([^)]*)\s*)/g

		const matches = code.matchAll(hardcodedAddressPattern)
		for (const match of matches) {
			const [fullMatch, address] = match

			vulnerabilities.push({
				id: `access-control-hardcoded-address-${vulnerabilities.length + 1}`,
				title: "Access Control: Hardcoded address",
				description: `Hardcoded address detected: ${address}`,
				category: "access_control" as VulnerabilityCategory,
				severity: "high" as VulnerabilitySeverity,
				source: "access-control-detector",
				locations: [
					{
						file: params.contractPath,
						line: 0,
						column: 0,
						function: "unknown",
						contract: params.contractName || "Unknown",
					},
				],
				confidence: 90,
				impact: "Hardcoded addresses can be exploited to create backdoors or allow attackers to bypass access controls. They can be used to grant special privileges or drain funds.",
				exploitScenario:
					"An attacker can exploit hardcoded addresses to create backdoors or grant themselves special privileges. For example, if there's a hardcoded address like `0x1234567890abcdef...`, an attacker can use it to bypass access controls or drain funds.",
				remediation:
					"Never hardcode addresses. Use address(this) or msg.sender for all address references. Consider using OpenZeppelin's Address pattern.",
				references: [
					"https://docs.soliditylang.org/en/developing-smart-contracts/security-considerations/",
					"https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/Address.sol",
				],
			})
		}

		return vulnerabilities
	}

	/**
	 * Helper method to check if a function has any access control modifier
	 */
	private hasAccessControlModifier(functionName: string): boolean {
		const accessControlModifiers = ["public", "private", "internal", "external", "viewable", "pure"]
		return accessControlModifiers.some((mod) => functionName.toLowerCase().includes(mod.toLowerCase()))
	}
}
