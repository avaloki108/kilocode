// kilocode_change - new file

/**
 * Plugin Registry for Managing Security Plugins
 * 
 * This module provides a centralized registry for managing security plugins.
 * 
 * @see WEB3-SECURITY-PLATFORM-ARCHITECTURE.md
 */

import type { ISecurityPlugin, PluginMetadata, PluginState, PluginCapability } from "./SecurityPlugin.js"
import type { VulnerabilityReport } from "../../../packages/core-schemas/src/web3-security/vulnerability.js"

/**
 * Plugin registry configuration
 */
export interface PluginRegistryConfig {
	/** Plugin storage directory */
	pluginDir: string
	/** Enable auto-discovery */
	autoDiscovery: boolean
	/** Enable auto-update */
	autoUpdate: boolean
	/** Marketplace URL */
	marketplaceUrl?: string
}

/**
 * Plugin registration info
 */
export interface PluginRegistration {
	/** Plugin instance */
	plugin: ISecurityPlugin
	/** Plugin metadata */
	metadata: PluginMetadata
	/** Registration timestamp */
	registeredAt: number
	/** Last updated timestamp */
	updatedAt?: number
}

/**
 * Plugin filter options
 */
export interface PluginFilter {
	/** Filter by capability */
	capability?: PluginCapability
	/** Filter by chain */
	chain?: string
	/** Filter by state */
	state?: PluginState
	/** Filter by author */
	author?: string
}

/**
 * Plugin registry for managing security plugins
 */
export class PluginRegistry {
	private config: PluginRegistryConfig
	private plugins: Map<string, PluginRegistration> = new Map()
	private eventListeners: Map<string, Set<Function>> = new Map()

	constructor(config: PluginRegistryConfig) {
		this.config = config
	}

	/**
	 * Register a plugin
	 */
	async registerPlugin(plugin: ISecurityPlugin): Promise<void> {
		const metadata = await plugin.getMetadata()
		const registration: PluginRegistration = {
			plugin,
			metadata,
			registeredAt: Date.now(),
		}

		this.plugins.set(metadata.id, registration)
		this.emit("plugin:registered", registration)
	}

	/**
	 * Unregister a plugin
	 */
	async unregisterPlugin(pluginId: string): Promise<void> {
		const registration = this.plugins.get(pluginId)
		if (!registration) {
			throw new Error(`Plugin not found: ${pluginId}`)
		}

		await registration.plugin.uninstall()
		this.plugins.delete(pluginId)
		this.emit("plugin:unregistered", registration)
	}

	/**
	 * Get a plugin by ID
	 */
	getPlugin(pluginId: string): ISecurityPlugin | undefined {
		const registration = this.plugins.get(pluginId)
		return registration?.plugin
	}

	/**
	 * Get plugin metadata by ID
	 */
	getPluginMetadata(pluginId: string): PluginMetadata | undefined {
		const registration = this.plugins.get(pluginId)
		return registration?.metadata
	}

	/**
	 * Get all registered plugins
	 */
	getAllPlugins(): ISecurityPlugin[] {
		return Array.from(this.plugins.values()).map((r) => r.plugin)
	}

	/**
	 * Get all plugin metadata
	 */
	getAllPluginMetadata(): PluginMetadata[] {
		return Array.from(this.plugins.values()).map((r) => r.metadata)
	}

	/**
	 * Get plugins by filter
	 */
	getPluginsByFilter(filter: PluginFilter): ISecurityPlugin[] {
		return Array.from(this.plugins.values())
			.filter((r) => {
				if (filter.capability && !r.metadata.capabilities.includes(filter.capability)) {
					return false
				}
				if (filter.chain && !r.metadata.supportedChains.includes(filter.chain)) {
					return false
				}
				if (filter.state && r.plugin.getState() !== filter.state) {
					return false
				}
				if (filter.author && r.metadata.author !== filter.author) {
					return false
				}
				return true
			})
			.map((r) => r.plugin)
	}

	/**
	 * Get plugins by capability
	 */
	getPluginsByCapability(capability: PluginCapability): ISecurityPlugin[] {
		return this.getPluginsByFilter({ capability })
	}

	/**
	 * Get plugins by chain
	 */
	getPluginsByChain(chain: string): ISecurityPlugin[] {
		return this.getPluginsByFilter({ chain })
	}

	/**
	 * Enable a plugin
	 */
	async enablePlugin(pluginId: string): Promise<void> {
		const registration = this.plugins.get(pluginId)
		if (!registration) {
			throw new Error(`Plugin not found: ${pluginId}`)
		}

		await registration.plugin.enable()
		this.emit("plugin:enabled", registration)
	}

	/**
	 * Disable a plugin
	 */
	async disablePlugin(pluginId: string): Promise<void> {
		const registration = this.plugins.get(pluginId)
		if (!registration) {
			throw new Error(`Plugin not found: ${pluginId}`)
		}

		await registration.plugin.disable()
		this.emit("plugin:disabled", registration)
	}

	/**
	 * Update a plugin
	 */
	async updatePlugin(pluginId: string): Promise<void> {
		const registration = this.plugins.get(pluginId)
		if (!registration) {
			throw new Error(`Plugin not found: ${pluginId}`)
		}

		await registration.plugin.update()
		registration.updatedAt = Date.now()
		this.emit("plugin:updated", registration)
	}

	/**
	 * Execute a plugin
	 */
	async executePlugin(
		pluginId: string,
		/** Analysis context */
		context: any,
		/** Configuration options */
		options?: Record<string, any>,
	): Promise<any> {
		const registration = this.plugins.get(pluginId)
		if (!registration) {
			throw new Error(`Plugin not found: ${pluginId}`)
		}

		const result = await registration.plugin.execute(context, options)
		this.emit("plugin:executed", { registration, result })
		return result
	}

	/**
	 * Check if a plugin is registered
	 */
	hasPlugin(pluginId: string): boolean {
		return this.plugins.has(pluginId)
	}

	/**
	 * Get plugin count
	 */
	getPluginCount(): number {
		return this.plugins.size
	}

	/**
	 * Get enabled plugin count
	 */
	getEnabledPluginCount(): number {
		return Array.from(this.plugins.values()).filter((r) => r.plugin.getState() === "enabled").length
	}

	/**
	 * Get disabled plugin count
	 */
	getDisabledPluginCount(): number {
		return Array.from(this.plugins.values()).filter((r) => r.plugin.getState() === "disabled").length
	}

	/**
	 * Clear all plugins
	 */
	async clearAllPlugins(): Promise<void> {
		const pluginIds = Array.from(this.plugins.keys())
		for (const pluginId of pluginIds) {
			await this.unregisterPlugin(pluginId)
		}
	}

	/**
	 * Register event listener
	 */
	on(event: string, listener: Function): void {
		if (!this.eventListeners.has(event)) {
			this.eventListeners.set(event, new Set())
		}
		this.eventListeners.get(event)!.add(listener)
	}

	/**
	 * Unregister event listener
	 */
	off(event: string, listener: Function): void {
		const listeners = this.eventListeners.get(event)
		if (listeners) {
			listeners.delete(listener)
		}
	}

	/**
	 * Emit event
	 */
	private emit(event: string, data: any): void {
		const listeners = this.eventListeners.get(event)
		if (listeners) {
			for (const listener of listeners) {
				try {
					listener(data)
				} catch (error) {
					console.error(`Error in event listener for ${event}:`, error)
				}
			}
		}
	}
}
