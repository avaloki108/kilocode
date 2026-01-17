// kilocode_change - new file

/**
 * Logic Error Detection Agent
 *
 * This module provides pattern-based detection for logic errors in smart contracts.
 * Logic errors can lead to unexpected behavior, funds loss, or contract lock-up.
 *
 * @see https://swcregistry.io/docs/SWC-110
 */

import type {
	Vulnerability,
	VulnerabilityCategory,
	CodeLocation,
} from "../../packages/core-schemas/src/web3-security/vulnerability.js"
import { VulnerabilityDetector, DetectionParams } from "./VulnerabilityDetector.js"

/**
 * Logic Error detection patterns
 */
enum LogicErrorPattern {
	/**
	 * Detects functions that return incorrect values
	 * (e.g., always returning false instead of proper error handling)
	 */
	ALWAYS_FALSE_RETURN = "always_false_return",

	/**
	 * Detects unreachable code paths
	 * (e.g., code that can never be executed)
	 */
	UNREACHABLE_CODE = "unreachable_code",

	/**
	 * Detects functions that don't return values
	 * (e.g., functions with no return statement)
	 */
	NO_RETURN_VALUE = "no_return_value",

	/**
	 * Detects inconsistent state checks
	 * (e.g., checking conditions in wrong order)
	 */
	INCONSISTENT_STATE_CHECKS = "inconsistent_state_checks",

	/**
	 * Detects incorrect boolean logic
	 * (e.g., using ! instead of || or incorrect comparison operators)
	 */
	INCORRECT_BOOLEAN_LOGIC = "incorrect_boolean_logic",

	/**
	 * Detects integer division issues
	 * (e.g., integer division that can result in incorrect values)
	 */
	INTEGER_DIVISION_ISSUES = "integer_division_issues",

	/**
	 * Detects array/index out of bounds
	 * (e.g., accessing array elements beyond length)
	 */
	ARRAY_INDEX_OUT_OF_BOUNDS = "array_index_out_of_bounds",

	/**
	 * Detects uninitialized storage variables
	 * (e.g., reading storage before writing)
	 */
	UNINITIALIZED_STORAGE = "uninitialized_storage",

	/**
	 * Detects uninitialized function pointers
	 * (e.g., calling functions before they're assigned)
	 */
	UNINITIALIZED_FUNCTION_POINTERS = "uninitialized_function_pointers",

	/**
	 * Detects missing null checks
	 * (e.g., not checking for null/undefined values)
	 */
	MISSING_NULL_CHECKS = "missing_null_checks",

	/**
	 * Detects potential infinite loops
	 * (e.g., loops without proper exit conditions)
	 */
	POTENTIAL_INFINITE_LOOPS = "potential_infinite_loops",

	/**
	 * Detects incorrect error handling
	 * (e.g., not handling revert conditions properly)
	 */
	INCORRECT_ERROR_HANDLING = "incorrect_error_handling",

	/**
	 * Detects timestamp manipulation
	 * (e.g., using block.timestamp for critical operations)
	 */
	TIMESTAMP_MANIPULATION = "timestamp_manipulation",

	/**
	 * Detects tx.origin usage for authorization
	 * (e.g., using tx.origin instead of msg.sender)
	 */
	TX_ORIGIN_AUTHORIZATION = "tx_origin_authorization",

	/**
	 * Detects delegatecall without access control
	 * (e.g., using delegatecall without proper checks)
	 */
	UNSAFE_DELEGATECALL = "unsafe_delegatecall",

	/**
	 * Detects self-destruct without proper checks
	 * (e.g., allowing anyone to call self-destruct)
	 */
	UNSAFE_SELF_DESTRUCT = "unsafe_self_destruct",

	/**
	 * Detects storage array manipulation
	 * (e.g., modifying array lengths without proper bounds checking)
	 */
	STORAGE_ARRAY_MANIPULATION = "storage_array_manipulation",

	/**
	 * Detects call stack manipulation
	 * (e.g., using inline assembly to manipulate call stack)
	 */
	CALL_STACK_MANIPULATION = "call_stack_manipulation",
}

/**
 * Logic Error Detection Agent
 */
export class LogicErrorDetectionAgent extends VulnerabilityDetector {
	readonly detectorId = "logic-error"
	readonly detectorName = "Logic Error Detection Agent"
	readonly supportedCategories: VulnerabilityCategory[] = ["logic_error"]
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
		super("logic-error")
	}

	/**
	 * Detect logic errors in the provided code
	 */
	async detect(params: DetectionParams): Promise<Vulnerability[]> {
		this.validateParams(params)
		const code = params.code
		const vulnerabilities: Vulnerability[] = []

		// Detect functions that always return false
		vulnerabilities.push(...this.detectAlwaysFalseReturn(code))

		// Detect unreachable code
		vulnerabilities.push(...this.detectUnreachableCode(code))

		// Detect functions without return values
		vulnerabilities.push(...this.detectNoReturnValue(code))

		// Detect inconsistent state checks
		vulnerabilities.push(...this.detectInconsistentStateChecks(code))

		// Detect incorrect boolean logic
		vulnerabilities.push(...this.detectIncorrectBooleanLogic(code))

		// Detect integer division issues
		vulnerabilities.push(...this.detectIntegerDivisionIssues(code))

		// Detect array index out of bounds
		vulnerabilities.push(...this.detectArrayIndexOutOfBounds(code))

		// Detect uninitialized storage variables
		vulnerabilities.push(...this.detectUninitializedStorage(code))

		// Detect uninitialized function pointers
		vulnerabilities.push(...this.detectUninitializedFunctionPointers(code))

		// Detect missing null checks
		vulnerabilities.push(...this.detectMissingNullChecks(code))

		// Detect potential infinite loops
		vulnerabilities.push(...this.detectPotentialInfiniteLoops(code))

		// Detect incorrect error handling
		vulnerabilities.push(...this.detectIncorrectErrorHandling(code))

		// Detect timestamp manipulation
		vulnerabilities.push(...this.detectTimestampManipulation(code))

		// Detect tx.origin usage
		vulnerabilities.push(...this.detectTxOriginAuthorization(code))

		// Detect unsafe delegatecall
		vulnerabilities.push(...this.detectUnsafeDelegatecall(code))

		// Detect unsafe self-destruct
		vulnerabilities.push(...this.detectUnsafeSelfDestruct(code))

		// Detect storage array manipulation
		vulnerabilities.push(...this.detectStorageArrayManipulation(code))

		// Detect call stack manipulation
		vulnerabilities.push(...this.detectCallStackManipulation(code))

		return vulnerabilities
	}

	/**
	 * Detect functions that always return false
	 */
	private detectAlwaysFalseReturn(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []
		const lines = code.split("\n")

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i]

			// Look for functions that always return false
			const alwaysFalsePattern = /function\s+([a-zA-Z_][a-zA-Z0-9]*)\s*\(\s*{\s*return\s*false\s*;?\s*}\s*}/gi
			const alwaysFalseMatch = line.match(alwaysFalsePattern)

			if (alwaysFalseMatch) {
				const functionName = alwaysFalseMatch[1]

				vulnerabilities.push({
					id: `${this.detectorId}-always-false-${i}`,
					source: this.detectorId,
					severity: "medium",
					category: "logic_error",
					title: "Function Always Returns False",
					description: `Function '${functionName}' always returns false regardless of input. This indicates a logic error that could cause unexpected contract behavior.`,
					locations: [
						{
							file: params.filePath || "unknown",
							line: i + 1,
							column: 0,
							function: functionName,
						},
					],
					metadata: {
						pattern: LogicErrorPattern.ALWAYS_FALSE_RETURN,
					},
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect unreachable code
	 */
	private detectUnreachableCode(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []
		const lines = code.split("\n")

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i]

			// Look for code after return, require, or revert statements
			const unreachablePattern = /(return|require|revert)\s*;\s*(unreachable|dead\s*code)/gi
			const unreachableMatch = line.match(unreachablePattern)

			if (unreachableMatch) {
				vulnerabilities.push({
					id: `${this.detectorId}-unreachable-${i}`,
					source: this.detectorId,
					severity: "low",
					category: "logic_error",
					title: "Unreachable Code",
					description:
						"Code exists after a return, require, or revert statement that makes it unreachable. This indicates dead code or a logic error.",
					locations: [
						{
							file: params.filePath || "unknown",
							line: i + 1,
							column: 0,
						},
					],
					metadata: {
						pattern: LogicErrorPattern.UNREACHABLE_CODE,
					},
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect functions without return values
	 */
	private detectNoReturnValue(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []
		const lines = code.split("\n")

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i]

			// Look for functions without return statements
			const noReturnPattern = /function\s+([a-zA-Z_][a-zA-Z0-9]*)\s*\([^)]*\)\s*\{[^}]*\}/gi
			const noReturnMatch = line.match(noReturnPattern)

			if (noReturnMatch) {
				const functionName = noReturnMatch[1]

				// Check if function has any return statement
				const hasReturn = /return\s*[^;]*;/gi.test(line)

				if (!hasReturn) {
					vulnerabilities.push({
						id: `${this.detectorId}-no-return-${i}`,
						source: this.detectorId,
						severity: "medium",
						category: "logic_error",
						title: "Function Has No Return Value",
						description: `Function '${functionName}' does not have a return statement. This could cause unexpected behavior or undefined values.`,
						locations: [
							{
								file: params.filePath || "unknown",
								line: i + 1,
								column: 0,
								function: functionName,
							},
						],
					})
				}
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect inconsistent state checks
	 */
	private detectInconsistentStateChecks(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []
		const lines = code.split("\n")

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i]

			// Look for state checks in wrong order
			const stateCheckPattern = /require\s*\([^)]+\s*)\s*;\s*(if\s*\([^)]+\s*)\s*(!\s*[^)]+\s*)\s*{\s*}\s*}/gi
			const stateCheckMatch = line.match(stateCheckPattern)

			if (stateCheckMatch) {
				const condition = stateCheckMatch[1]
				const requirement = stateCheckMatch[2]

				vulnerabilities.push({
					id: `${this.detectorId}-inconsistent-state-${i}`,
					source: this.detectorId,
					severity: "low",
					category: "logic_error",
					title: "Inconsistent State Checks",
					description: `State check '${condition}' is performed after '${requirement}'. This could indicate a logic error where the contract checks conditions in the wrong order.`,
					locations: [
						{
							file: params.filePath || "unknown",
							line: i + 1,
							column: 0,
						},
					],
					metadata: {
						pattern: LogicErrorPattern.INCONSISTENT_STATE_CHECKS,
						condition,
						requirement,
					},
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect incorrect boolean logic
	 */
	private detectIncorrectBooleanLogic(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []
		const lines = code.split("\n")

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i]

			// Look for incorrect boolean operations
			const incorrectBooleanPattern = /(!\s*[^)]+\s*)\s*(\s*[^)]+\s*)\s*(\s*[^)]+\s*)\s*(!\s*[^)]+\s*)/gi
			const incorrectBooleanMatch = line.match(incorrectBooleanPattern)

			if (incorrectBooleanMatch) {
				vulnerabilities.push({
					id: `${this.detectorId}-incorrect-boolean-${i}`,
					source: this.detectorId,
					severity: "medium",
					category: "logic_error",
					title: "Incorrect Boolean Logic",
					description: `Incorrect boolean logic detected: '${incorrectBooleanMatch[0]}'. This could lead to unexpected behavior.`,
					locations: [
						{
							file: params.filePath || "unknown",
							line: i + 1,
							column: 0,
						},
					],
					metadata: {
						pattern: LogicErrorPattern.INCORRECT_BOOLEAN_LOGIC,
					},
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect integer division issues
	 */
	private detectIntegerDivisionIssues(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []
		const lines = code.split("\n")

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i]

			// Look for integer division without overflow protection
			const divisionPattern = /\/\s*\d+\s*/gi
			const divisionMatch = line.match(divisionPattern)

			if (divisionMatch) {
				vulnerabilities.push({
					id: `${this.detectorId}-integer-division-${i}`,
					source: this.detectorId,
					severity: "high",
					category: "logic_error",
					title: "Integer Division Issue",
					description:
						"Integer division detected without overflow protection. This could result in incorrect values or truncated results.",
					locations: [
						{
							file: params.filePath || "unknown",
							line: i + 1,
							column: 0,
						},
					],
					metadata: {
						pattern: LogicErrorPattern.INTEGER_DIVISION_ISSUES,
					},
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect array index out of bounds
	 */
	private detectArrayIndexOutOfBounds(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []
		const lines = code.split("\n")

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i]

			// Look for array access without bounds checking
			const arrayAccessPattern = /\[a-zA-Z_][a-zA-Z0-9]*\]\s*\s*(\s*[a-zA-Z_][a-zA-Z0-9]*\s*)\s*\s*[^)]+\s*/gi
			const arrayAccessMatch = line.match(arrayAccessPattern)

			if (arrayAccessMatch) {
				const arrayName = arrayAccessMatch[1]
				const index = arrayAccessMatch[2]

				vulnerabilities.push({
					id: `${this.detectorId}-array-oob-${i}`,
					source: this.detectorId,
					severity: "high",
					category: "logic_error",
					title: "Array Index Out of Bounds",
					description: `Array '${arrayName}' is accessed at index '${index}' without bounds checking. This could cause out-of-bounds access.`,
					locations: [
						{
							file: params.filePath || "unknown",
							line: i + 1,
							column: 0,
						},
					],
					metadata: {
						pattern: LogicErrorPattern.ARRAY_INDEX_OUT_OF_BOUNDS,
						arrayName,
						index,
					},
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect uninitialized storage variables
	 */
	private detectUninitializedStorage(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []
		const lines = code.split("\n")

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i]

			// Look for storage reads before writes
			const storagePattern = /(\w*(balance|totalSupply|allowance|mapping|count|owner|status)\s*\s*=\s*[^,;]\s*)/gi
			const storageMatch = line.match(storagePattern)

			if (storageMatch) {
				const variable = storageMatch[1]

				vulnerabilities.push({
					id: `${this.detectorId}-uninitialized-storage-${i}`,
					source: this.detectorId,
					severity: "high",
					category: "logic_error",
					title: "Uninitialized Storage Variable",
					description: `Storage variable '${variable}' is read before being written to. This could return incorrect values and lead to unexpected behavior.`,
					locations: [
						{
							file: params.filePath || "unknown",
							line: i + 1,
							column: 0,
						},
					],
					metadata: {
						pattern: LogicErrorPattern.UNINITIALIZED_STORAGE,
						variable,
					},
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect uninitialized function pointers
	 */
	private detectUninitializedFunctionPointers(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []
		const lines = code.split("\n")

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i]

			// Look for function calls before assignment
			const functionPointerPattern = /function\s+([a-zA-Z_][a-zA-Z0-9]*)\s*\([^)]+\s*)\s*=\s*[^,;]\s*)/gi
			const functionPointerMatch = line.match(functionPointerPattern)

			if (functionPointerMatch) {
				const functionName = functionPointerMatch[1]
				const pointer = functionPointerMatch[2]

				vulnerabilities.push({
					id: `${this.detectorId}-uninitialized-pointer-${i}`,
					source: this.detectorId,
					severity: "high",
					category: "logic_error",
					title: "Uninitialized Function Pointer",
					description: `Function '${functionName}' is called via pointer '${pointer}' before being assigned. This could lead to undefined behavior.`,
					locations: [
						{
							file: params.filePath || "unknown",
							line: i + 1,
							column: 0,
						},
					],
					metadata: {
						pattern: LogicErrorPattern.UNINITIALIZED_FUNCTION_POINTERS,
						functionName,
						pointer,
					},
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect missing null checks
	 */
	private detectMissingNullChecks(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []
		const lines = code.split("\n")

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i]

			// Look for missing null/undefined checks
			const nullCheckPattern = /if\s*\([^)]+\s*)\s*(==|!=)\s*(null|undefined)\s*[^)]+\s*)/gi
			const nullCheckMatch = line.match(nullCheckPattern)

			if (nullCheckMatch) {
				const variable = nullCheckMatch[1]
				const operator = nullCheckMatch[2]
				const value = nullCheckMatch[3]

				vulnerabilities.push({
					id: `${this.detectorId}-missing-null-check-${i}`,
					source: this.detectorId,
					severity: "medium",
					category: "logic_error",
					title: "Missing Null Check",
					description: `Variable '${variable}' is compared using '${operator}' without checking for null/undefined. This could cause unexpected behavior when the value is null.`,
					locations: [
						{
							file: params.filePath || "unknown",
							line: i + 1,
							column: 0,
						},
					],
					metadata: {
						pattern: LogicErrorPattern.MISSING_NULL_CHECKS,
						variable,
						operator,
						value,
					},
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect potential infinite loops
	 */
	private detectPotentialInfiniteLoops(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []
		const lines = code.split("\n")

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i]

			// Look for loops without proper exit conditions
			const loopPattern = /for\s*\(\s*;\s*[^)]+\s*)\s*{\s*}\s*}/gi
			const loopMatch = line.match(loopPattern)

			if (loopMatch) {
				vulnerabilities.push({
					id: `${this.detectorId}-potential-infinite-loop-${i}`,
					source: this.detectorId,
					severity: "medium",
					category: "logic_error",
					title: "Potential Infinite Loop",
					description:
						"Loop detected without clear exit condition. This could cause the contract to hang or run indefinitely.",
					locations: [
						{
							file: params.filePath || "unknown",
							line: i + 1,
							column: 0,
						},
					],
					metadata: {
						pattern: LogicErrorPattern.POTENTIAL_INFINITE_LOOPS,
					},
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect incorrect error handling
	 */
	private detectIncorrectErrorHandling(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []
		const lines = code.split("\n")

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i]

			// Look for incorrect revert handling
			const revertPattern = /revert\s*\([^)]+\s*)\s*;\s*require\s*\([^)]+\s*)\s*}/gi
			const revertMatch = line.match(revertPattern)

			if (revertMatch) {
				vulnerabilities.push({
					id: `${this.detectorId}-incorrect-error-handling-${i}`,
					source: this.detectorId,
					severity: "high",
					category: "logic_error",
					title: "Incorrect Error Handling",
					description:
						"Revert statement without proper condition check. This could cause the contract to revert in unintended situations.",
					locations: [
						{
							file: params.filePath || "unknown",
							line: i + 1,
							column: 0,
						},
					],
					metadata: {
						pattern: LogicErrorPattern.INCORRECT_ERROR_HANDLING,
					},
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect timestamp manipulation
	 */
	private detectTimestampManipulation(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []
		const lines = code.split("\n")

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i]

			// Look for block.timestamp usage in critical operations
			const timestampPattern = /block\.timestamp\s*\([^)]+\s*)/gi
			const timestampMatch = line.match(timestampPattern)

			if (timestampMatch) {
				vulnerabilities.push({
					id: `${this.detectorId}-timestamp-manipulation-${i}`,
					source: this.detectorId,
					severity: "high",
					category: "logic_error",
					title: "Timestamp Manipulation",
					description:
						"block.timestamp is used in a critical operation. This makes the transaction predictable and could be exploited by front-running.",
					locations: [
						{
							file: params.filePath || "unknown",
							line: i + 1,
							column: 0,
						},
					],
					metadata: {
						pattern: LogicErrorPattern.TIMESTAMP_MANIPULATION,
					},
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect tx.origin usage for authorization
	 */
	private detectTxOriginAuthorization(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []
		const lines = code.split("\n")

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i]

			// Look for tx.origin usage
			const txOriginPattern = /tx\.origin\s*\([^)]+\s*)/gi
			const txOriginMatch = line.match(txOriginPattern)

			if (txOriginMatch) {
				vulnerabilities.push({
					id: `${this.detectorId}-tx-origin-${i}`,
					source: this.detectorId,
					severity: "high",
					category: "logic_error",
					title: "TX Origin Authorization",
					description:
						"tx.origin is used for authorization instead of msg.sender. This is insecure and allows for authorization bypass attacks.",
					locations: [
						{
							file: params.filePath || "unknown",
							line: i + 1,
							column: 0,
						},
					],
					metadata: {
						pattern: LogicErrorPattern.TX_ORIGIN_AUTHORIZATION,
					},
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect unsafe delegatecall
	 */
	private detectUnsafeDelegatecall(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []
		const lines = code.split("\n")

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i]

			// Look for delegatecall without access control
			const delegatecallPattern = /delegatecall\s*\([^)]+\s*)/gi
			const delegatecallMatch = line.match(delegatecallPattern)

			if (delegatecallMatch) {
				vulnerabilities.push({
					id: `${this.detectorId}-unsafe-delegatecall-${i}`,
					source: this.detectorId,
					severity: "critical",
					category: "logic_error",
					title: "Unsafe Delegatecall",
					description:
						"delegatecall is used without proper access control checks. This could allow attackers to execute arbitrary code in the target contract.",
					locations: [
						{
							file: params.filePath || "unknown",
							line: i + 1,
							column: 0,
						},
					],
					metadata: {
						pattern: LogicErrorPattern.UNSAFE_DELEGATECALL,
					},
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect unsafe self-destruct
	 */
	private detectUnsafeSelfDestruct(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []
		const lines = code.split("\n")

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i]

			// Look for selfdestruct without access control
			const selfdestructPattern = /selfdestruct\s*\([^)]+\s*)\s*\([^)]+\s*)/gi
			const selfdestructMatch = line.match(selfdestructPattern)

			if (selfdestructMatch) {
				vulnerabilities.push({
					id: `${this.detectorId}-unsafe-selfdestruct-${i}`,
					source: this.detectorId,
					severity: "critical",
					category: "logic_error",
					title: "Unsafe Self-Destruct",
					description:
						"selfdestruct function is accessible without proper access control. This could allow anyone to destroy the contract.",
					locations: [
						{
							file: params.filePath || "unknown",
							line: i + 1,
							column: 0,
						},
					],
					metadata: {
						pattern: LogicErrorPattern.UNSAFE_SELF_DESTRUCT,
					},
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect storage array manipulation
	 */
	private detectStorageArrayManipulation(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []
		const lines = code.split("\n")

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i]

			// Look for array length modifications without proper checks
			const arrayManipulationPattern = /\.length\s*=\s*[^;]\s*/gi
			const arrayManipulationMatch = line.match(arrayManipulationPattern)

			if (arrayManipulationMatch) {
				vulnerabilities.push({
					id: `${this.detectorId}-storage-array-manipulation-${i}`,
					source: this.detectorId,
					severity: "high",
					category: "logic_error",
					title: "Storage Array Manipulation",
					description:
						"Storage array length is modified without proper bounds checking. This could cause out-of-bounds access or storage corruption.",
					locations: [
						{
							file: params.filePath || "unknown",
							line: i + 1,
							column: 0,
						},
					],
					metadata: {
						pattern: LogicErrorPattern.STORAGE_ARRAY_MANIPULATION,
					},
				})
			}
		}

		return vulnerabilities
	}

	/**
	 * Detect call stack manipulation
	 */
	private detectCallStackManipulation(code: string): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []
		const lines = code.split("\n")

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i]

			// Look for inline assembly that manipulates call stack
			const callStackPattern = /assembly\s*["\^]*\s*callvalue\s*[^)]+\s*)/gi
			const callStackMatch = line.match(callStackPattern)

			if (callStackMatch) {
				vulnerabilities.push({
					id: `${this.detectorId}-call-stack-manipulation-${i}`,
					source: this.detectorId,
					severity: "critical",
					category: "logic_error",
					title: "Call Stack Manipulation",
					description:
						"Inline assembly is used to manipulate the call stack. This could be used to bypass access control or execute arbitrary code.",
					locations: [
						{
							file: params.filePath || "unknown",
							line: i + 1,
							column: 0,
						},
					],
					metadata: {
						pattern: LogicErrorPattern.CALL_STACK_MANIPULATION,
					},
				})
			}
		}

		return vulnerabilities
	}
}
