// kilocode_change - new file

/**
 * Security Plugin Base Class and Interface
 * 
 * This module provides the base class and interface for security plugins.
 * 
 * @see WEB3-SECURITY-PLATFORM-ARCHITECTURE.md
 */

import type { VulnerabilityReport, Vulnerability } from "../../../packages/core-schemas/src/web3-security/vulnerability.js"

/**
 * Plugin capabilities
 */
export type PluginCapability =
	| "static-analysis"
	| "dynamic-analysis"
	| "fuzzing"
	| "symbolic-execution"
	| "blockchain-interaction"
	| "report-generation"
	| "vulnerability-detection"
	| "real-time-monitoring"

/**
 * Plugin state
 */
export type PluginState = "disabled" | "enabled" | "loading" | "error" | "updating"

/**
 * Plugin metadata
 */
export interface PluginMetadata {
	/** Plugin ID */
	id: string
	/** Plugin name */
	name: string
	/** Plugin version */
	version: string
	/** Plugin description */
	description: string
	/** Plugin author */
	author: string
	/** Plugin capabilities */
	capabilities: PluginCapability[]
	/** Supported chains */
	supportedChains: string[]
	/** Plugin icon */
	icon?: string
	/** Plugin homepage */
	homepage?: string
	/** Plugin repository */
	repository?: string
	/** Plugin license */
	license: string
	/** Plugin dependencies */
	dependencies?: string[]
}

/**
 * Plugin configuration
 */
export interface PluginConfiguration {
	/** Configuration options */
	options: Record<string, any>
	/** Default settings */
	settings: Record<string, any>
}

/**
 * Plugin execution result
 */
export interface PluginExecutionResult {
	/** Success */
	success: boolean
	/** Output data */
	data?: any
	/** Error message */
	error?: string
	/** Execution time */
	executionTime?: number
}

/**
 * Security Plugin Interface
 */
export interface ISecurityPlugin {
	/** Get plugin metadata */
	getMetadata(): Promise<PluginMetadata>

	/**
	 * Initialize plugin
	 */
	initialize(config: PluginConfiguration): Promise<void>

	/**
	 * Execute plugin
	 */
	execute(
		/** Analysis context */
		context: any,
		/** Configuration options */
		options?: Record<string, any>,
	): Promise<PluginExecutionResult>

	/**
	 * Get plugin state
	 */
	getState(): PluginState

	/**
	 * Enable plugin
	 */
	enable(): Promise<void>

	/**
	 * Disable plugin
	 */
	disable(): Promise<void>

	/**
	 * Update plugin
	 */
	update(): Promise<void>

	/**
	 * Uninstall plugin
	 */
	uninstall(): Promise<void>

	/**
	 * Get plugin capabilities
	 */
	getCapabilities(): PluginCapability[]

	/**
	 * Check if plugin is compatible with context
	 */
	isCompatibleWithContext(context: any): boolean
}
