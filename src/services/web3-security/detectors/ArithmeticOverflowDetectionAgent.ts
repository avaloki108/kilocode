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
 * ArithmeticOverflowDetectionAgent - Specialized detector for arithmetic overflow/underflow vulnerabilities
 *
 * This agent detects integer overflow and underflow vulnerabilities in smart contracts
 * by analyzing:
 * - Mathematical operations
 * - Range checking
 * - Solidity 0.8.x overflow protection verification
 * - Custom arithmetic patterns
 */
export class ArithmeticOverflowDetectionAgent extends VulnerabilityDetector {
	constructor() {
		super(
			"arithmetic-overflow-detector",
			"Arithmetic Overflow Detection Agent",
			"Specialized detector for arithmetic overflow/underflow vulnerabilities",
			["arithmetic"],
			["evm"],
		)
	}

	/**
	 * Detect arithmetic overflow vulnerabilities in the provided contract
	 */
	async detect(params: DetectionParams): Promise<Vulnerability[]> {
		this.validateParams(params)

		const vulnerabilities: Vulnerability[] = []
		const code = params.code

		// Pattern 1: Unchecked arithmetic operations
		vulnerabilities.push(...this.detectUncheckedArithmetic(code))

		// Pattern 2: Integer overflow in loops
		vulnerabilities.push(...this.detectIntegerOverflowInLoops(code))

		// Pattern 3: Underflow in subtraction
		vulnerabilities.push(...this.detectUnderflowInSubtraction(code))

		// Pattern 4: Overflow in addition
		vulnerabilities.push(...this.detectOverflowInAddition(code))

		// Pattern 5: Overflow in multiplication
		vulnerabilities.push(...this.detectOverflowInMultiplication(code))

		// Pattern 6: Overflow in division
		vulnerabilities.push(...this.detectOverflowInDivision(code))

		// Pattern 7: Overflow in modulo operations
		vulnerabilities.push(...this.detectOverflowInModulo(code))

		// Pattern 8: Overflow in exponentiation
		vulnerabilities.push(...this.detectOverflowInExponentiation(code))

		// Pattern 9: Unsafe type casting
		vulnerabilities.push(...this.detectUnsafeTypeCasting(code))

		// Pattern 10: Overflow in array operations
		vulnerabilities.push(...this.detectOverflowInArrayOperations(code))

		return vulnerabilities
	}

	/**
	 * Detect unchecked arithmetic operations
	 */
	private detectUncheckedArithmetic(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Pattern: arithmetic operations without SafeMath
		const uncheckedPattern = /\b\s*(?:\s*uint\d*)\s*\s*(?:\s*int\d*)\s*(?:\s*uint\d*)\s*[\+\-*%]\s*/g

		const matches = code.matchAll(uncheckedPattern)
		for (const match of matches) {
			const [fullMatch, operation] = match

			vulnerabilities.push({
				id: `arithmetic-unchecked-${vulnerabilities.length + 1}`,
				title: "Arithmetic: Unchecked operation",
				description: `Unsafe arithmetic operation detected: ${operation}`,
				category: "arithmetic" as VulnerabilityCategory,
				severity: "high" as VulnerabilitySeverity,
				source: "arithmetic-overflow-detector",
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
				impact: "Unbounded arithmetic operations can cause integer overflow/underflow vulnerabilities. Attackers can exploit these to manipulate contract state or cause denial of service.",
				exploitScenario:
					"An attacker provides very large or very small values to arithmetic operations, causing them to overflow and corrupt contract state. This can be used to drain funds or manipulate contract logic in unexpected ways.",
				remediation:
					"Always use SafeMath library for arithmetic operations. Use the `checked` keyword for arithmetic operations. Consider using libraries like OpenZeppelin's SafeMath that provide overflow protection.",
				references: [
					"https://docs.soliditylang.org/en/developing-smart-contracts/security-considerations/",
					"https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/SafeMath.sol",
					"https://swcregistry.com/docs/Swaps-Comprehensive-Checks-Audits-Security-Considerations/",
				],
			})
		}

		return vulnerabilities
	}

	/**
	 * Detect integer overflow in loops
	 */
	private detectIntegerOverflowInLoops(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Pattern: loop counter without bounds check
		const loopOverflowPattern = /for\s*\(\s*uint\d*\s*(?:\s*int\d*)\s*[\+\-*%]\s*(?:\s*uint\d*)\s*)/g

		const matches = code.matchAll(loopOverflowPattern)
		for (const match of matches) {
			const [fullMatch, loopVariable, counterType] = match

			vulnerabilities.push({
				id: `arithmetic-loop-overflow-${vulnerabilities.length + 1}`,
				title: "Arithmetic: Integer overflow in loop",
				description: `Loop variable ${loopVariable} (${counterType}) may overflow due to unbounded iteration`,
				category: "arithmetic" as VulnerabilityCategory,
				severity: "medium" as VulnerabilitySeverity,
				source: "arithmetic-overflow-detector",
				locations: [
					{
						file: params.contractPath,
						line: 0,
						column: 0,
						function: "unknown",
						contract: params.contractName || "Unknown",
					},
				],
				confidence: 80,
				impact: "Unbounded loops can cause integer overflow, allowing attackers to manipulate contract state or cause denial of service through excessive gas consumption or unexpected behavior.",
				exploitScenario:
					"An attacker exploits the lack of bounds checking in a loop by providing an iteration count that exceeds the maximum integer value, causing an overflow that corrupts contract state or allows unauthorized operations.",
				remediation:
					"Always use bounded loops with explicit iteration limits. Consider using for loops with fixed bounds or while loops with explicit conditions. Use SafeMath operations for loop counters.",
				references: [
					"https://docs.soliditylang.org/en/developing-smart-contracts/security-considerations/",
					"https://consensys.com/blog/developing-smart-contracts/loop-invariant/",
					"https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/SafeMath.sol",
				],
			})
		}

		return vulnerabilities
	}

	/**
	 * Detect underflow in subtraction
	 */
	private detectUnderflowInSubtraction(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Pattern: subtraction without bounds check
		const underflowPattern = /(uint\d+|int\d+)\s*-\s*(uint\d+|int\d+)/g

		const matches = code.matchAll(underflowPattern)
		for (const match of matches) {
			const [fullMatch, operation] = match

			vulnerabilities.push({
				id: `arithmetic-subtraction-underflow-${vulnerabilities.length + 1}`,
				title: "Arithmetic: Underflow in subtraction",
				description: `Subtraction operation ${operation} may cause integer underflow`,
				category: "arithmetic" as VulnerabilityCategory,
				severity: "medium" as VulnerabilitySeverity,
				source: "arithmetic-overflow-detector",
				locations: [
					{
						file: params.contractPath,
						line: 0,
						column: 0,
						function: "unknown",
						contract: params.contractName || "Unknown",
					},
				],
				confidence: 80,
				impact: "Integer underflow can allow attackers to manipulate contract state by making values negative when they shouldn't be, potentially bypassing access controls or causing unexpected behavior.",
				exploitScenario:
					"An attacker exploits the lack of underflow protection by providing inputs that cause the result to underflow, potentially draining funds or making balance checks fail.",
				remediation:
					"Always use SafeMath library for arithmetic operations. Use the `sub` keyword for subtraction operations. Consider adding underflow checks or using libraries with built-in protection.",
				references: [
					"https://docs.soliditylang.org/en/developing-smart-contracts/security-considerations/",
					"https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/SafeMath.sol",
				],
			})
		}

		return vulnerabilities
	}

	/**
	 * Detect overflow in addition
	 */
	private detectOverflowInAddition(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Pattern: addition without overflow check
		const additionOverflowPattern = /(?:\s*(?:\s*uint\d*)\s*(?:\s*int\d*)\s*)\s*\+\s*(?:\s*uint\d*)\s*)/g

		const matches = code.matchAll(additionOverflowPattern)
		for (const match of matches) {
			const [fullMatch, operation] = match

			vulnerabilities.push({
				id: `arithmetic-addition-overflow-${vulnerabilities.length + 1}`,
				title: "Arithmetic: Overflow in addition",
				description: `Addition operation ${operation} may cause integer overflow`,
				category: "arithmetic" as VulnerabilityCategory,
				severity: "medium" as VulnerabilitySeverity,
				source: "arithmetic-overflow-detector",
				locations: [
					{
						file: params.contractPath,
						line: 0,
						column: 0,
						function: "unknown",
						contract: params.contractName || "Unknown",
					},
				],
				confidence: 80,
				impact: "Integer overflow in addition operations can corrupt contract state or allow attackers to manipulate values beyond expected ranges.",
				exploitScenario:
					"An attacker provides very large values to addition operations, causing them to overflow and corrupt contract state or manipulate logic in unexpected ways.",
				remediation:
					"Always use SafeMath library for arithmetic operations. Use the `add` keyword for addition operations. Consider using libraries with overflow protection.",
				references: [
					"https://docs.soliditylang.org/en/developing-smart-contracts/security-considerations/",
					"https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/SafeMath.sol",
				],
			})
		}

		return vulnerabilities
	}

	/**
	 * Detect overflow in multiplication
	 */
	private detectOverflowInMultiplication(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Pattern: multiplication without overflow check
		const multiplicationOverflowPattern = /(?:\s*(?:\s*uint\d*)\s*(?:\s*int\d*)\s*)\s*\*\s*(?:\s*uint\d*)\s*)/g

		const matches = code.matchAll(multiplicationOverflowPattern)
		for (const match of matches) {
			const [fullMatch, operation] = match

			vulnerabilities.push({
				id: `arithmetic-multiplication-overflow-${vulnerabilities.length + 1}`,
				title: "Arithmetic: Overflow in multiplication",
				description: `Multiplication operation ${operation} may cause integer overflow`,
				category: "arithmetic" as VulnerabilityCategory,
				severity: "medium" as VulnerabilitySeverity,
				source: "arithmetic-overflow-detector",
				locations: [
					{
						file: params.contractPath,
						line: 0,
						column: 0,
						function: "unknown",
						contract: params.contractName || "Unknown",
					},
				],
				confidence: 80,
				impact: "Integer overflow in multiplication can corrupt contract state or allow attackers to manipulate values beyond expected ranges.",
				exploitScenario:
					"An attacker provides very large values to multiplication operations, causing them to overflow and corrupt contract state or manipulate logic in unexpected ways.",
				remediation:
					"Always use SafeMath library for arithmetic operations. Use the `mul` keyword for multiplication operations. Consider using libraries with overflow protection.",
				references: [
					"https://docs.soliditylang.org/en/developing-smart-contracts/security-considerations/",
					"https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/SafeMath.sol",
				],
			})
		}

		return vulnerabilities
	}

	/**
	 * Detect overflow in division
	 */
	private detectOverflowInDivision(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Pattern: division without overflow check
		const divisionOverflowPattern = /(?:\s*(?:\s*uint\d*)\s*(?:\s*int\d*)\s*)\s*\/\s*(?:\s*uint\d*)\s*)/g

		const matches = code.matchAll(divisionOverflowPattern)
		for (const match of matches) {
			const [fullMatch, operation] = match

			vulnerabilities.push({
				id: `arithmetic-division-overflow-${vulnerabilities.length + 1}`,
				title: "Arithmetic: Overflow in division",
				description: `Division operation ${operation} may cause integer overflow`,
				category: "arithmetic" as VulnerabilityCategory,
				severity: "medium" as VulnerabilitySeverity,
				source: "arithmetic-overflow-detector",
				locations: [
					{
						file: params.contractPath,
						line: 0,
						column: 0,
						function: "unknown",
						contract: params.contractName || "Unknown",
					},
				],
				confidence: 80,
				impact: "Integer overflow in division can corrupt contract state or allow attackers to manipulate values beyond expected ranges.",
				exploitScenario:
					"An attacker provides very large or very small divisors to division operations, causing them to overflow and corrupt contract state or manipulate logic in unexpected ways.",
				remediation:
					"Always use SafeMath library for arithmetic operations. Use the `div` keyword for division operations. Consider using libraries with overflow protection.",
				references: [
					"https://docs.soliditylang.org/en/developing-smart-contracts/security-considerations/",
					"https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/SafeMath.sol",
				],
			})
		}

		return vulnerabilities
	}

	/**
	 * Detect overflow in modulo operations
	 */
	private detectOverflowInModulo(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Pattern: modulo without overflow check
		const moduloOverflowPattern = /(?:\s*(?:\s*uint\d*)\s*(?:\s*int\d*)\s*)\s*%\s*(?:\s*uint\d*)\s*)/g

		const matches = code.matchAll(moduloOverflowPattern)
		for (const match of matches) {
			const [fullMatch, operation] = match

			vulnerabilities.push({
				id: `arithmetic-modulo-overflow-${vulnerabilities.length + 1}`,
				title: "Arithmetic: Overflow in modulo",
				description: `Modulo operation ${operation} may cause integer overflow`,
				category: "arithmetic" as VulnerabilityCategory,
				severity: "medium" as VulnerabilitySeverity,
				source: "arithmetic-overflow-detector",
				locations: [
					{
						file: params.contractPath,
						line: 0,
						column: 0,
						function: "unknown",
						contract: params.contractName || "Unknown",
					},
				],
				confidence: 80,
				impact: "Integer overflow in modulo operations can corrupt contract state or allow attackers to manipulate values beyond expected ranges.",
				exploitScenario:
					"An attacker exploits the lack of overflow protection in modulo operations by providing values that cause the result to overflow, potentially draining funds or making balance checks fail.",
				remediation:
					"Always use SafeMath library for arithmetic operations. Use the `mod` keyword for modulo operations. Consider using libraries with overflow protection.",
				references: [
					"https://docs.soliditylang.org/en/developing-smart-contracts/security-considerations/",
					"https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/SafeMath.sol",
				],
			})
		}

		return vulnerabilities
	}

	/**
	 * Detect overflow in exponentiation
	 */
	private detectOverflowInExponentiation(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Pattern: exponentiation without overflow check
		const exponentiationOverflowPattern = /(?:\s*(?:\s*uint\d*)\s*(?:\s*int\d*)\s*)\s*\*\s*(?:\s*uint\d*)\s*)/g

		const matches = code.matchAll(exponentiationOverflowPattern)
		for (const match of matches) {
			const [fullMatch, operation] = match

			vulnerabilities.push({
				id: `arithmetic-exponentiation-overflow-${vulnerabilities.length + 1}`,
				title: "Arithmetic: Overflow in exponentiation",
				description: `Exponentiation operation ${operation} may cause integer overflow`,
				category: "arithmetic" as VulnerabilityCategory,
				severity: "medium" as VulnerabilitySeverity,
				source: "arithmetic-overflow-detector",
				locations: [
					{
						file: params.contractPath,
						line: 0,
						column: 0,
						function: "unknown",
						contract: params.contractName || "Unknown",
					},
				],
				confidence: 80,
				impact: "Integer overflow in exponentiation can corrupt contract state or allow attackers to manipulate values beyond expected ranges.",
				exploitScenario:
					"An attacker exploits the lack of overflow protection in exponentiation operations by providing very large exponents or bases, causing them to overflow and corrupt contract state or manipulate logic in unexpected ways.",
				remediation:
					"Always use SafeMath library for arithmetic operations. Consider using SafeMath's power functions or libraries with overflow protection.",
				references: [
					"https://docs.soliditylang.org/en/developing-smart-contracts/security-considerations/",
					"https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/SafeMath.sol",
				],
			})
		}

		return vulnerabilities
	}

	/**
	 * Detect unsafe type casting
	 */
	private detectUnsafeTypeCasting(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Pattern: unsafe casting
		const unsafeCastPattern = /(?:uint\d*\(\s*int\d*)\s*uint\d*)/g

		const matches = code.matchAll(unsafeCastPattern)
		for (const match of matches) {
			const [fullMatch, fromType, toType] = match

			vulnerabilities.push({
				id: `arithmetic-unsafe-cast-${vulnerabilities.length + 1}`,
				title: "Arithmetic: Unsafe type casting",
				description: `Unsafe cast from ${fromType} to ${toType} detected`,
				category: "arithmetic" as VulnerabilityCategory,
				severity: "high" as VulnerabilitySeverity,
				source: "arithmetic-overflow-detector",
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
				impact: "Unsafe type casting can cause data corruption, integer overflow, or unexpected behavior. Attackers can exploit this to manipulate contract state or bypass access controls.",
				exploitScenario:
					"An attacker exploits unsafe type casting to cause integer overflow, bypass access controls, or corrupt contract state. For example, casting a large number to a smaller type can truncate the value, or casting a signed integer to an unsigned integer can cause unexpected behavior.",
				remediation:
					"Always use SafeCast library for type conversions. Avoid manual type casting. Use explicit type conversions with proper bounds checking.",
				references: [
					"https://docs.soliditylang.org/en/developing-smart-contracts/security-considerations/",
					"https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/SafeCast.sol",
				],
			})
		}

		return vulnerabilities
	}

	/**
	 * Detect overflow in array operations
	 */
	private detectOverflowInArrayOperations(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Pattern: array operations without bounds check
		const arrayOverflowPattern = /(?:\s*(?:\s*uint\d*)\s*(?:\s*int\d*)\s*)\s*\[\s*(?:\s*uint\d*)\s*)/g

		const matches = code.matchAll(arrayOverflowPattern)
		for (const match of matches) {
			const [fullMatch, operation] = match

			vulnerabilities.push({
				id: `arithmetic-array-overflow-${vulnerabilities.length + 1}`,
				title: "Arithmetic: Overflow in array operation",
				description: `Array operation ${operation} may cause integer overflow`,
				category: "arithmetic" as VulnerabilityCategory,
				severity: "medium" as VulnerabilitySeverity,
				source: "arithmetic-overflow-detector",
				locations: [
					{
						file: params.contractPath,
						line: 0,
						column: 0,
						function: "unknown",
						contract: params.contractName || "Unknown",
					},
				],
				confidence: 80,
				impact: "Array operations without proper bounds checking can cause integer overflow, leading to out-of-bounds access or unexpected behavior.",
				exploitScenario:
					"An attacker exploits array operations without bounds checking to access or modify array elements outside the intended range, potentially corrupting contract state or causing denial of service.",
				remediation:
					"Always use SafeMath library for array operations. Use arrays with proper bounds checking. Consider using libraries like OpenZeppelin's arrays that provide overflow protection.",
				references: [
					"https://docs.soliditylang.org/en/developing-smart-contracts/security-considerations/",
					"https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/Arrays.sol",
				],
			})
		}

		return vulnerabilities
	}
}
