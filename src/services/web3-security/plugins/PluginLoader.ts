// kilocode_change - new file

/**
 * Plugin Loader for Dynamic Plugin Discovery
 * 
 * This module provides dynamic plugin discovery and loading capabilities.
 * 
 * @see WEB3-SECURITY-PLATFORM-ARCHITECTURE.md
 */

import type { ISecurityPlugin, PluginMetadata, PluginConfiguration } from "./SecurityPlugin.js"
import type { PluginRegistry } from "./PluginRegistry.js"

/**
 * Plugin loader configuration
 */
export interface PluginLoaderConfig {
	/** Plugin directories to scan */
	pluginDirs: string[]
	/** File patterns to match */
	filePatterns: string[]
	/** Enable auto-loading */
	autoLoad: boolean
	/** Enable hot-reload */
	hotReload: boolean
	/** Plugin manifest filename */
	manifestFilename: string
}

/**
 * Plugin discovery result
 */
export interface PluginDiscoveryResult {
	/** Discovered plugins */
	plugins: DiscoveredPlugin[]
	/** Discovery errors */
	errors: Array<{ path: string; error: string }>
}

/**
 * Discovered plugin
 */
export interface DiscoveredPlugin {
	/** Plugin path */
	path: string
	/** Plugin manifest */
	manifest: PluginMetadata
	/** Plugin class */
	pluginClass?: new () => ISecurityPlugin
	/** Load error */
	error?: string
}

/**
 * Plugin load result
 */
export interface PluginLoadResult {
	/** Success */
	success: boolean
	/** Plugin ID */
	pluginId?: string
	/** Error message */
	error?: string
}

/**
 * Plugin loader for dynamic plugin discovery
 */
export class PluginLoader {
	private config: PluginLoaderConfig
	private registry: PluginRegistry
	private loadedPlugins: Map<string, ISecurityPlugin> = new Map()
	private watchers: Map<string, any> = new Map()

	constructor(config: PluginLoaderConfig, registry: PluginRegistry) {
		this.config = config
		this.registry = registry
	}

	/**
	 * Discover plugins in configured directories
	 */
	async discoverPlugins(): Promise<PluginDiscoveryResult> {
		const result: PluginDiscoveryResult = {
			plugins: [],
			errors: [],
		}

		for (const pluginDir of this.config.pluginDirs) {
			const dirResult = await this.discoverPluginsInDirectory(pluginDir)
			result.plugins.push(...dirResult.plugins)
			result.errors.push(...dirResult.errors)
		}

		return result
	}

	/**
	 * Discover plugins in a specific directory
	 */
	private async discoverPluginsInDirectory(
		pluginDir: string,
	): Promise<{ plugins: DiscoveredPlugin[]; errors: Array<{ path: string; error: string }> }> {
		const result = {
			plugins: [] as DiscoveredPlugin[],
			errors: [] as Array<{ path: string; error: string }>,
		}

		try {
			// Use fs to scan directory for manifest files
			const { readdir, readFile, stat } = await import("fs/promises")
			const { join } = await import("path")

			const entries = await readdir(pluginDir, { withFileTypes: true })

			for (const entry of entries) {
				if (!entry.isDirectory()) {
					continue
				}

				const pluginPath = join(pluginDir, entry.name)
				const manifestPath = join(pluginPath, this.config.manifestFilename)

				try {
					const manifestStat = await stat(manifestPath)
					if (!manifestStat.isFile()) {
						continue
					}

					const manifestContent = await readFile(manifestPath, "utf-8")
					const manifest: PluginMetadata = JSON.parse(manifestContent)

					const discovered: DiscoveredPlugin = {
						path: pluginPath,
						manifest,
					}

					// Try to load plugin class
					try {
						const pluginClass = await this.loadPluginClass(pluginPath, manifest)
						discovered.pluginClass = pluginClass
					} catch (error) {
						discovered.error = String(error)
					}

					result.plugins.push(discovered)
				} catch (error) {
					result.errors.push({
						path: pluginPath,
						error: String(error),
					})
				}
			}
		} catch (error) {
			result.errors.push({
				path: pluginDir,
				error: String(error),
			})
		}

		return result
	}

	/**
	 * Load plugin class from path
	 */
	private async loadPluginClass(
		pluginPath: string,
		manifest: PluginMetadata,
	): Promise<new () => ISecurityPlugin> {
		const { join } = await import("path")

		// Try to load the main entry point
		const mainEntry = manifest.main || "index.js"
		const entryPath = join(pluginPath, mainEntry)

		// Dynamic import
		const module = await import(entryPath)

		// Find the default export or named export matching plugin ID
		const pluginClass =
			module.default ||
			module[manifest.id] ||
			module[manifest.name.replace(/[^a-zA-Z0-9]/g, "")]

		if (!pluginClass) {
			throw new Error(`No plugin class found in ${entryPath}`)
		}

		return pluginClass
	}

	/**
	 * Load a plugin
	 */
	async loadPlugin(
		pluginPath: string,
		manifest: PluginMetadata,
		config?: PluginConfiguration,
	): Promise<PluginLoadResult> {
		try {
			const pluginClass = await this.loadPluginClass(pluginPath, manifest)
			const plugin = new pluginClass()

			// Initialize plugin
			const pluginConfig: PluginConfiguration = config || {
				options: {},
				settings: {},
			}

			await plugin.initialize(pluginConfig)

			// Register plugin
			await this.registry.registerPlugin(plugin)
			this.loadedPlugins.set(manifest.id, plugin)

			return {
				success: true,
				pluginId: manifest.id,
			}
		} catch (error) {
			return {
				success: false,
				error: String(error),
			}
		}
	}

	/**
	 * Load all discovered plugins
	 */
	async loadAllPlugins(
		discoveryResult: PluginDiscoveryResult,
	): Promise<PluginLoadResult[]> {
		const results: PluginLoadResult[] = []

		for (const discovered of discoveryResult.plugins) {
			if (discovered.error) {
				results.push({
					success: false,
					error: discovered.error,
				})
				continue
			}

			const result = await this.loadPlugin(discovered.path, discovered.manifest)
			results.push(result)
		}

		return results
	}

	/**
	 * Unload a plugin
	 */
	async unloadPlugin(pluginId: string): Promise<void> {
		const plugin = this.loadedPlugins.get(pluginId)
		if (!plugin) {
			throw new Error(`Plugin not loaded: ${pluginId}`)
		}

		await plugin.disable()
		await this.registry.unregisterPlugin(pluginId)
		this.loadedPlugins.delete(pluginId)
	}

	/**
	 * Reload a plugin
	 */
	async reloadPlugin(pluginId: string): Promise<PluginLoadResult> {
		// Unload existing plugin
		const plugin = this.loadedPlugins.get(pluginId)
		if (!plugin) {
			return {
				success: false,
				error: `Plugin not loaded: ${pluginId}`,
			}
		}

		const manifest = await plugin.getMetadata()

		// Unload
		await this.unloadPlugin(pluginId)

		// Rediscover and reload
		const discoveryResult = await this.discoverPlugins()
		const discovered = discoveryResult.plugins.find((p) => p.manifest.id === pluginId)

		if (!discovered) {
			return {
				success: false,
				error: `Plugin not found after reload: ${pluginId}`,
			}
		}

		return await this.loadPlugin(discovered.path, discovered.manifest)
	}

	/**
	 * Start watching for plugin changes
	 */
	async startWatching(): Promise<void> {
		if (!this.config.hotReload) {
			return
		}

		const { watch } = await import("fs")

		for (const pluginDir of this.config.pluginDirs) {
			const watcher = watch(pluginDir, { recursive: true }, async (eventType, filename) => {
				if (eventType === "change" && filename) {
					// Reload affected plugin
					await this.reloadAffectedPlugin(pluginDir, filename)
				}
			})

			this.watchers.set(pluginDir, watcher)
		}
	}

	/**
	 * Stop watching for plugin changes
	 */
	async stopWatching(): Promise<void> {
		for (const [pluginDir, watcher] of this.watchers) {
			watcher.close()
			this.watchers.delete(pluginDir)
		}
	}

	/**
	 * Reload affected plugin on file change
	 */
	private async reloadAffectedPlugin(pluginDir: string, filename: string): Promise<void> {
		const { join } = await import("path")
		const { readdir } = await import("fs/promises")

		try {
			// Find which plugin directory contains the file
			const entries = await readdir(pluginDir, { withFileTypes: true })

			for (const entry of entries) {
				if (!entry.isDirectory()) {
					continue
				}

				const pluginPath = join(pluginDir, entry.name)
				const filePath = join(pluginPath, filename)

				try {
					const { stat } = await import("fs/promises")
					await stat(filePath)

					// File is in this plugin directory
					const discoveryResult = await this.discoverPluginsInDirectory(pluginPath)
					if (discoveryResult.plugins.length > 0) {
						const discovered = discoveryResult.plugins[0]
						await this.reloadPlugin(discovered.manifest.id)
					}

					break
				} catch {
					// File not in this plugin directory
				}
			}
		} catch (error) {
			console.error("Error reloading affected plugin:", error)
		}
	}

	/**
	 * Get loaded plugins
	 */
	getLoadedPlugins(): ISecurityPlugin[] {
		return Array.from(this.loadedPlugins.values())
	}

	/**
	 * Check if a plugin is loaded
	 */
	isPluginLoaded(pluginId: string): boolean {
		return this.loadedPlugins.has(pluginId)
	}

	/**
	 * Get loaded plugin count
	 */
	getLoadedPluginCount(): number {
		return this.loadedPlugins.size
	}
}
