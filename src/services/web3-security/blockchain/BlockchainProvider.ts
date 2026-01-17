// kilocode_change - new file

/**
 * Blockchain Provider Interface and Implementations
 * 
 * This module provides the blockchain provider interface and implementations
 * for interacting with EVM and non-EVM chains.
 * 
 * @see WEB3-SECURITY-PLATFORM-ARCHITECTURE.md
 */

/**
 * Chain type
 */
export type ChainType = "evm" | "solana" | "cosmos" | "polkadot" | "near" | "aptos" | "sui" | "movr"

/**
 * EVM chain
 */
export type EVMChain =
	| "ethereum"
	| "bsc"
	| "polygon"
	| "arbitrum"
	| "optimism"
	| "avalanche"
	| "fantom"
	| "aurora"
	| "moonbeam"
	| "celo"
	| "harmony"
	| "cronos"

/**
 * Transaction result
 */
export interface TransactionResult {
	/** Transaction hash */
	hash: string
	/** Block number */
	blockNumber?: number
	/** Gas used */
	gasUsed: number
	/** Status */
	status: "success" | "failed" | "pending"
	/** Error message */
	error?: string
	/** Return value */
	returnValue?: string
	/** Events emitted */
	events?: any[]
}

/**
 * Contract state
 */
export interface ContractState {
	/** Contract address */
	address: string
	/** Balance */
	balance: string
	/** Storage values */
	storage?: Record<string, string>
	/** State variables */
	state?: Record<string, any>
}

/**
 * Block info
 */
export interface BlockInfo {
	/** Block number */
	number: number
	/** Block hash */
	hash: string
	/** Timestamp */
	timestamp: number
	/** Gas limit */
	gasLimit: number
	/** Gas used */
	gasUsed: number
}

/**
 * Blockchain Provider Configuration
 */
export interface BlockchainProviderConfig {
	/** Chain type */
	chainType: ChainType
	/** RPC endpoint */
	rpcEndpoint: string
	/** Chain ID (for EVM) */
	chainId?: number
	/** Private key (optional, for write operations) */
	privateKey?: string
	/** Timeout in milliseconds */
	timeout?: number
}

/**
 * Blockchain Provider Interface
 */
export interface IBlockchainProvider {
	/** Provider configuration */
	readonly config: BlockchainProviderConfig

	/**
	 * Connect to blockchain
	 */
	connect(): Promise<void>

	/**
	 * Disconnect from blockchain
	 */
	disconnect(): Promise<void>

	/**
	 * Get block info
	 */
	getBlock(blockNumber: number | "latest"): Promise<BlockInfo>

	/**
	 * Get contract state
	 */
	getContractState(contractAddress: string): Promise<ContractState>

	/**
	 * Read contract
	 */
	readContract(
		contractAddress: string,
		functionName: string,
		args?: any[],
	): Promise<any>

	/**
	 * Write contract
	 */
	writeContract(
		contractAddress: string,
		functionName: string,
		args?: any[],
		value?: string,
		gasLimit?: number,
	): Promise<TransactionResult>

	/**
	 * Simulate transaction
	 */
	simulateTransaction(
		contractAddress: string,
		functionName: string,
		args?: any[],
		value?: string,
	): Promise<TransactionResult>

	/**
	 * Estimate gas
	 */
	estimateGas(
		contractAddress: string,
		functionName: string,
		args?: any[],
		value?: string,
	): Promise<number>

	/**
	 * Get transaction receipt
	 */
	getTransactionReceipt(txHash: string): Promise<any>

	/**
	 * Get balance
	 */
	getBalance(address: string): Promise<string>

	/**
	 * Send transaction
	 */
	sendTransaction(
		to: string,
		value?: string,
		data?: string,
		gasLimit?: number,
	): Promise<TransactionResult>

	/**
	 * Get current block number
	 */
	getCurrentBlockNumber(): Promise<number>

	/**
	 * Wait for transaction
	 */
	waitForTransaction(txHash: string, confirmations?: number): Promise<TransactionResult>
}
