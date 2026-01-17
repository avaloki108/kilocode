// kilocode_change - new file

/**
 * Plugin Lifecycle Manager
 * 
 * This module provides lifecycle management for security plugins including
 * install, enable, disable, and update operations.
 * 
 * @see WEB3-SECURITY-PLATFORM-ARCHITECTURE.md
 */

import type { ISecurityPlugin, PluginMetadata, PluginConfiguration, PluginState } from "./SecurityPlugin.js"
import type { PluginRegistry } from "./PluginRegistry.js"
import type { PluginLoader } from "./PluginLoader.js"

/**
 * Plugin installation source
 */
export type PluginInstallSource =
	| "local"
	| "marketplace"
	| "git"
	| "npm"
	| "url"

/**
 * Plugin installation options
 */
export interface PluginInstallOptions {
	/** Plugin source */
	source: PluginInstallSource
	/** Plugin URL or path */
	location: string
	/** Install version */
	version?: string
	/** Force reinstall */
	force?: boolean
	/** Skip dependencies */
	skipDependencies?: boolean
}

/**
 * Plugin update options
 */
export interface PluginUpdateOptions {
	/** Check for updates only */
	checkOnly?: boolean
	/** Update to specific version */
	version?: string
	/** Force update */
	force?: boolean
}

/**
 * Plugin lifecycle event
 */
export interface PluginLifecycleEvent {
	/** Event type */
	type: "install" | "enable" | "disable" | "update" | "uninstall"
	/** Plugin ID */
	pluginId: string
	/** Timestamp */
	timestamp: number
	/** Success */
	success: boolean
	/** Error message */
	error?: string
	/** Additional data */
	data?: any
}

/**
 * Plugin lifecycle manager
 */
export class PluginLifecycleManager {
	private registry: PluginRegistry
	private loader: PluginLoader
	private eventHistory: PluginLifecycleEvent[] = []
	private eventListeners: Map<string, Set<Function>> = new Map()

	constructor(registry: PluginRegistry, loader: PluginLoader) {
		this.registry = registry
		this.loader = loader
	}

	/**
	 * Install a plugin
	 */
	async installPlugin(options: PluginInstallOptions): Promise<void> {
		const { source, location, version, force, skipDependencies } = options

		try {
			// Check if plugin already exists
			const pluginId = this.extractPluginId(location)
			if (!force && this.registry.hasPlugin(pluginId)) {
				throw new Error(`Plugin already installed: ${pluginId}`)
			}

			// Install based on source type
			switch (source) {
				case "local":
					await this.installFromLocal(location, version)
					break
				case "marketplace":
					await this.installFromMarketplace(location, version)
					break
				case "git":
					await this.installFromGit(location, version)
					break
				case "npm":
					await this.installFromNpm(location, version)
					break
				case "url":
					await this.installFromUrl(location, version)
					break
				default:
					throw new Error(`Unsupported install source: ${source}`)
			}

			// Load plugin
			const discoveryResult = await this.loader.discoverPlugins()
			const discovered = discoveryResult.plugins.find((p) => p.manifest.id === pluginId)

			if (!discovered) {
				throw new Error(`Plugin not found after installation: ${pluginId}`)
			}

			await this.loader.loadPlugin(discovered.path, discovered.manifest)

			// Install dependencies
			if (!skipDependencies && discovered.manifest.dependencies) {
				await this.installDependencies(discovered.manifest.dependencies)
			}

			// Record event
			this.recordEvent({
				type: "install",
				pluginId,
				timestamp: Date.now(),
				success: true,
				data: { source, location, version },
			})
		} catch (error) {
			this.recordEvent({
				type: "install",
				pluginId: this.extractPluginId(location),
				timestamp: Date.now(),
				success: false,
				error: String(error),
			})
			throw error
		}
	}

	/**
	 * Enable a plugin
	 */
	async enablePlugin(pluginId: string): Promise<void> {
		try {
			await this.registry.enablePlugin(pluginId)

			this.recordEvent({
				type: "enable",
				pluginId,
				timestamp: Date.now(),
				success: true,
			})
		} catch (error) {
			this.recordEvent({
				type: "enable",
				pluginId,
				timestamp: Date.now(),
				success: false,
				error: String(error),
			})
			throw error
		}
	}

	/**
	 * Disable a plugin
	 */
	async disablePlugin(pluginId: string): Promise<void> {
		try {
			await this.registry.disablePlugin(pluginId)

			this.recordEvent({
				type: "disable",
				pluginId,
				timestamp: Date.now(),
				success: true,
			})
		} catch (error) {
			this.recordEvent({
				type: "disable",
				pluginId,
				timestamp: Date.now(),
				success: false,
				error: String(error),
			})
			throw error
		}
	}

	/**
	 * Update a plugin
	 */
	async updatePlugin(pluginId: string, options: PluginUpdateOptions = {}): Promise<void> {
		const { checkOnly, version, force } = options

		try {
			const metadata = this.registry.getPluginMetadata(pluginId)
			if (!metadata) {
				throw new Error(`Plugin not found: ${pluginId}`)
			}

			// Check for updates
			const latestVersion = await this.checkForUpdates(pluginId, metadata)
			if (checkOnly) {
				if (latestVersion === metadata.version) {
					console.log(`Plugin ${pluginId} is up to date (${metadata.version})`)
				} else {
					console.log(`Update available for ${pluginId}: ${metadata.version} -> ${latestVersion}`)
				}
				return
			}

			// Determine target version
			const targetVersion = version || latestVersion

			if (!force && targetVersion === metadata.version) {
				console.log(`Plugin ${pluginId} is already at version ${targetVersion}`)
				return
			}

			// Uninstall current version
			await this.uninstallPlugin(pluginId, { keepConfig: true })

			// Install new version
			await this.installPlugin({
				source: "marketplace",
				location: pluginId,
				version: targetVersion,
				force: true,
			})

			this.recordEvent({
				type: "update",
				pluginId,
				timestamp: Date.now(),
				success: true,
				data: { from: metadata.version, to: targetVersion },
			})
		} catch (error) {
			this.recordEvent({
				type: "update",
				pluginId,
				timestamp: Date.now(),
				success: false,
				error: String(error),
			})
			throw error
		}
	}

	/**
	 * Uninstall a plugin
	 */
	async uninstallPlugin(
		pluginId: string,
		options: { keepConfig?: boolean } = {},
	): Promise<void> {
		try {
			// Keep or remove configuration
			if (!options.keepConfig) {
				await this.removePluginConfig(pluginId)
			}

			// Unregister from registry
			await this.registry.unregisterPlugin(pluginId)

			// Remove plugin files
			await this.removePluginFiles(pluginId)

			this.recordEvent({
				type: "uninstall",
				pluginId,
				timestamp: Date.now(),
				success: true,
			})
		} catch (error) {
			this.recordEvent({
				type: "uninstall",
				pluginId,
				timestamp: Date.now(),
				success: false,
				error: String(error),
			})
			throw error
		}
	}

	/**
	 * Check for updates
	 */
	private async checkForUpdates(pluginId: string, metadata: PluginMetadata): Promise<string | null> {
		// TODO: Implement marketplace API integration
		// For now, return null to indicate no update available
		return null
	}

	/**
	 * Install from local directory
	 */
	private async installFromLocal(path: string, version?: string): Promise<void> {
		const { copy } = await import("fs/promises")
		const { join } = await import("path")

		// Copy plugin to plugin directory
		const pluginDir = this.getPluginDirectory()
		const targetDir = join(pluginDir, path.split("/").pop()!)

		await copy(path, targetDir, { recursive: true })
	}

	/**
	 * Install from marketplace
	 */
	private async installFromMarketplace(pluginId: string, version?: string): Promise<void> {
		// TODO: Implement marketplace download
		throw new Error("Marketplace installation not yet implemented")
	}

	/**
	 * Install from Git repository
	 */
	private async installFromGit(url: string, version?: string): Promise<void> {
		// TODO: Implement Git clone
		throw new Error("Git installation not yet implemented")
	}

	/**
	 * Install from NPM
	 */
	private async installFromNpm(packageName: string, version?: string): Promise<void> {
		// TODO: Implement NPM install
		throw new Error("NPM installation not yet implemented")
	}

	/**
	 * Install from URL
	 */
	private async installFromUrl(url: string, version?: string): Promise<void> {
		// TODO: Implement URL download
		throw new Error("URL installation not yet implemented")
	}

	/**
	 * Install plugin dependencies
	 */
	private async installDependencies(dependencies: string[]): Promise<void> {
		for (const dep of dependencies) {
			try {
				await this.installPlugin({
					source: "marketplace",
					location: dep,
					skipDependencies: true,
				})
			} catch (error) {
				console.error(`Failed to install dependency ${dep}:`, error)
			}
		}
	}

	/**
	 * Remove plugin files
	 */
	private async removePluginFiles(pluginId: string): Promise<void> {
		const { rm } = await import("fs/promises")
		const { join } = await import("path")

		const pluginDir = join(this.getPluginDirectory(), pluginId)
		await rm(pluginDir, { recursive: true, force: true })
	}

	/**
	 * Remove plugin configuration
	 */
	private async removePluginConfig(pluginId: string): Promise<void> {
		// TODO: Implement config removal
		console.log(`Removing configuration for plugin: ${pluginId}`)
	}

	/**
	 * Get plugin directory
	 */
	private getPluginDirectory(): string {
		// TODO: Get from configuration
		return "/tmp/kilocode/plugins"
	}

	/**
	 * Extract plugin ID from location
	 */
	private extractPluginId(location: string): string {
		const parts = location.split("/")
		return parts[parts.length - 1] || location
	}

	/**
	 * Record lifecycle event
	 */
	private recordEvent(event: PluginLifecycleEvent): void {
		this.eventHistory.push(event)
		this.emit("lifecycle:event", event)
	}

	/**
	 * Get event history
	 */
	getEventHistory(pluginId?: string): PluginLifecycleEvent[] {
		if (pluginId) {
			return this.eventHistory.filter((e) => e.pluginId === pluginId)
		}
		return this.eventHistory
	}

	/**
	 * Clear event history
	 */
	clearEventHistory(): void {
		this.eventHistory = []
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
					console.error(`Error in lifecycle event listener for ${event}:`, error)
				}
			}
		}
	}
}
