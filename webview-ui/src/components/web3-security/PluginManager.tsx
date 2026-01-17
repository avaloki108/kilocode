// kilocode_change - new file

/**
 * Plugin Manager Component
 * 
 * This component provides a UI for managing security plugins
 * including discovery, installation, configuration, and lifecycle management.
 * 
 * @see WEB3-SECURITY-PLATFORM-ARCHITECTURE.md
 */

import React, { useState, useEffect } from "react"
import { VSCodeButton } from "@vscode/webview-ui-toolkit/react"

/**
 * Plugin info
 */
interface PluginInfo {
	id: string
	name: string
	version: string
	description: string
	author: string
	status: "disabled" | "enabled" | "error"
	capabilities: string[]
	supportedChains: string[]
	installed: boolean
}

/**
 * Plugin filter options
 */
interface PluginFilterOptions {
	/** Filter by status */
	status?: "all" | "enabled" | "disabled"
	/** Filter by capability */
	capability?: string
	/** Filter by chain */
	chain?: string
	/** Search query */
	query?: string
}

/**
 * Plugin manager props
 */
interface PluginManagerProps {
	/** On install callback */
	onInstall?: (pluginId: string) => void
	/** On uninstall callback */
	onUninstall?: (pluginId: string) => void
	/** On enable callback */
	onEnable?: (pluginId: string) => void
	/** On disable callback */
	onDisable?: (pluginId: string) => void
	/** On update callback */
	onUpdate?: (pluginId: string) => void
	/** On configure callback */
	onConfigure?: (pluginId: string) => void
	/** On refresh callback */
	onRefresh?: () => void
	/** Show installed only */
	showInstalledOnly?: boolean
}

/**
 * Plugin Manager Component
 */
export const PluginManager: React.FC<PluginManagerProps> = ({
	onInstall,
	onUninstall,
	onEnable,
	onDisable,
	onUpdate,
	onConfigure,
	onRefresh,
	showInstalledOnly = false,
}) => {
	const [plugins, setPlugins] = useState<PluginInfo[]>([])
	const [filter, setFilter] = useState<PluginFilterOptions>({})
	const [loading, setLoading] = useState(false)
	const [selectedPlugin, setSelectedPlugin] = useState<string | null>(null)
	const [showDetails, setShowDetails] = useState(false)
	const [installingId, setInstallingId] = useState<string | null>(null)
	const [error, setError] = useState<string | null>(null)

	// Load plugins on mount
	useEffect(() => {
		loadPlugins()
	}, [])

	// Load plugins
	const loadPlugins = async () => {
		setLoading(true)
		setError(null)

		try {
			// TODO: Load from plugin registry
			// For now, use mock data
			const mockPlugins: PluginInfo[] = [
				{
					id: "slither-integration",
					name: "Slither Integration",
					version: "1.0.0",
					description: "Static analysis tool for Solidity smart contracts",
					author: "Trail of Bits",
					status: "enabled",
					capabilities: ["static-analysis"],
					supportedChains: ["ethereum", "polygon", "bsc"],
					installed: true,
				},
				{
					id: "mythril-integration",
					name: "Mythril Integration",
					version: "0.2.0",
					description: "Symbolic execution tool for smart contracts",
					author: "Trail of Bits",
					status: "enabled",
					capabilities: ["symbolic-execution"],
					supportedChains: ["ethereum", "polygon"],
					installed: true,
				},
				{
					id: "foundry-integration",
					name: "Foundry Integration",
					version: "0.8.0",
					description: "Smart contract testing and fuzzing framework",
					author: "Foundry",
					status: "enabled",
					capabilities: ["fuzzing", "testing"],
					supportedChains: ["ethereum", "polygon", "bsc"],
					installed: true,
				},
				{
					id: "hardhat-integration",
					name: "Hardhat Integration",
					version: "2.12.0",
					description: "Smart contract development and testing framework",
					author: "Nomic Foundation",
					status: "disabled",
					capabilities: ["fuzzing", "testing"],
					supportedChains: ["ethereum", "polygon", "bsc"],
					installed: false,
				},
				{
					id: "echidna-integration",
					name: "Echidna Integration",
					version: "2.0.0",
					description: "Property-based fuzzing for smart contracts",
					author: "Trail of Bits",
					status: "disabled",
					capabilities: ["fuzzing"],
					supportedChains: ["ethereum"],
					installed: false,
				},
				{
					id: "manticore-integration",
					name: "Manticore Integration",
					version: "0.3.0",
					description: "Symbolic execution engine for smart contracts",
					author: "Trail of Bits",
					status: "disabled",
					capabilities: ["symbolic-execution"],
					supportedChains: ["ethereum"],
					installed: false,
				},
				{
					id: "maian-integration",
					name: "Maian Integration",
					version: "0.2.0",
					description: "Honeypot and vulnerability detection tool",
					author: "Trail of Bits",
					status: "disabled",
					capabilities: ["static-analysis"],
					supportedChains: ["ethereum"],
					installed: false,
				},
				{
					id: "reentrancy-detector",
					name: "Reentrancy Detector",
					version: "1.0.0",
					description: "Specialized detector for reentrancy vulnerabilities",
					author: "Kilo Code",
					status: "enabled",
					capabilities: ["vulnerability-detection"],
					supportedChains: ["ethereum", "polygon", "bsc", "solana"],
					installed: true,
				},
				{
					id: "arithmetic-overflow-detector",
					name: "Arithmetic Overflow Detector",
					version: "1.0.0",
					description: "Specialized detector for arithmetic overflow/underflow vulnerabilities",
					author: "Kilo Code",
					status: "enabled",
					capabilities: ["vulnerability-detection"],
					supportedChains: ["ethereum", "polygon", "bsc"],
					installed: true,
				},
				{
					id: "access-control-flaw-detector",
					name: "Access Control Flaw Detector",
					version: "1.0.0",
					description: "Specialized detector for access control flaws",
					author: "Kilo Code",
					status: "enabled",
					capabilities: ["vulnerability-detection"],
					supportedChains: ["ethereum", "polygon", "bsc"],
					installed: true,
				},
				{
					id: "front-running-detector",
					name: "Front Running Detector",
					version: "1.0.0",
					description: "Specialized detector for front-running vulnerabilities",
					author: "Kilo Code",
					status: "enabled",
					capabilities: ["vulnerability-detection"],
					supportedChains: ["ethereum", "polygon", "bsc"],
					installed: true,
				},
				{
					id: "logic-error-detector",
					name: "Logic Error Detector",
					version: "1.0.0",
					description: "Specialized detector for logic errors",
					author: "Kilo Code",
					status: "enabled",
					capabilities: ["vulnerability-detection"],
					supportedChains: ["ethereum", "polygon", "bsc"],
					installed: true,
				},
				{
					id: "solana-analysis-agent",
					name: "Solana Analysis Agent",
					version: "1.0.0",
					description: "Specialized detector for Solana-specific vulnerabilities",
					author: "Kilo Code",
					status: "enabled",
					capabilities: ["vulnerability-detection"],
					supportedChains: ["solana"],
					installed: true,
				},
			]

			setPlugins(mockPlugins)
			setLoading(false)
		} catch (err) {
			setError(`Failed to load plugins: ${String(err)}`)
			setLoading(false)
		}
	}

	// Filter plugins
	const filteredPlugins = plugins.filter((plugin) => {
		if (filter.status && filter.status !== "all" && plugin.status !== filter.status) {
			return false
		}
		if (filter.capability && !plugin.capabilities.includes(filter.capability)) {
			return false
		}
		if (filter.chain && !plugin.supportedChains.includes(filter.chain)) {
			return false
		}
		if (filter.query) {
			const query = filter.query.toLowerCase()
			return (
				plugin.name.toLowerCase().includes(query) ||
				plugin.description.toLowerCase().includes(query) ||
				plugin.id.toLowerCase().includes(query)
			)
		}
		return true
	})

	// Get status color
	const getStatusColor = (status: string): string => {
		switch (status) {
			case "enabled":
				return "text-green-500"
			case "disabled":
				return "text-gray-400"
			case "error":
				return "text-red-500"
			default:
				return "text-gray-400"
		}
	}

	// Install plugin
	const handleInstall = async (pluginId: string) => {
		setInstallingId(pluginId)
		setError(null)

		try {
			// TODO: Call plugin lifecycle manager
			console.log(`Installing plugin: ${pluginId}`)

			// Simulate installation delay
			await new Promise((resolve) => setTimeout(resolve, 1000))

			// Update plugin status
			setPlugins((prev) =>
				prev.map((p) =>
					p.id === pluginId ? { ...p, status: "enabled", installed: true } : p,
				),
			)

			if (onInstall) {
				onInstall(pluginId)
			}
		} catch (err) {
			setError(`Failed to install plugin: ${String(err)}`)
			setInstallingId(null)
		}
	}

	// Uninstall plugin
	const handleUninstall = async (pluginId: string) => {
		setLoading(true)
		setError(null)

		try {
			// TODO: Call plugin lifecycle manager
			console.log(`Uninstalling plugin: ${pluginId}`)

			// Simulate uninstall delay
			await new Promise((resolve) => setTimeout(resolve, 1000))

			// Update plugin status
			setPlugins((prev) => prev.filter((p) => p.id !== pluginId))

			if (onUninstall) {
				onUninstall(pluginId)
			}
		} catch (err) {
			setError(`Failed to uninstall plugin: ${String(err)}`)
		} finally {
			setLoading(false)
		}
	}

	// Enable plugin
	const handleEnable = async (pluginId: string) => {
		setLoading(true)
		setError(null)

		try {
			// TODO: Call plugin lifecycle manager
			console.log(`Enabling plugin: ${pluginId}`)

			// Simulate enable delay
			await new Promise((resolve) => setTimeout(resolve, 500))

			// Update plugin status
			setPlugins((prev) =>
				prev.map((p) =>
					p.id === pluginId ? { ...p, status: "enabled" } : p,
				),
			)

			if (onEnable) {
				onEnable(pluginId)
			}
		} catch (err) {
			setError(`Failed to enable plugin: ${String(err)}`)
		} finally {
			setLoading(false)
		}
	}

	// Disable plugin
	const handleDisable = async (pluginId: string) => {
		setLoading(true)
		setError(null)

		try {
			// TODO: Call plugin lifecycle manager
			console.log(`Disabling plugin: ${pluginId}`)

			// Simulate disable delay
			await new Promise((resolve) => setTimeout(resolve, 500))

			// Update plugin status
			setPlugins((prev) =>
				prev.map((p) =>
					p.id === pluginId ? { ...p, status: "disabled" } : p,
				),
			)

			if (onDisable) {
				onDisable(pluginId)
			}
		} catch (err) {
			setError(`Failed to disable plugin: ${String(err)}`)
		} finally {
			setLoading(false)
		}
	}

	// Update plugin
	const handleUpdate = async (pluginId: string) => {
		setLoading(true)
		setError(null)

		try {
			// TODO: Call plugin lifecycle manager
			console.log(`Updating plugin: ${pluginId}`)

			// Simulate update delay
			await new Promise((resolve) => setTimeout(resolve, 1500))

			if (onUpdate) {
				onUpdate(pluginId)
			}
		} catch (err) {
			setError(`Failed to update plugin: ${String(err)}`)
		} finally {
			setLoading(false)
		}
	}

	// Configure plugin
	const handleConfigure = (pluginId: string) => {
		setSelectedPlugin(pluginId)
		setShowDetails(true)
	}

	// Refresh
	const handleRefresh = () => {
		loadPlugins()
		if (onRefresh) {
			onRefresh()
		}
	}

	// Get stats
	const installedCount = plugins.filter((p) => p.installed).length
	const enabledCount = plugins.filter((p) => p.status === "enabled").length
	const disabledCount = plugins.filter((p) => p.status === "disabled").length

	return (
		<div className="flex flex-col h-full bg-vscode-editor-background">
			{/* Header */}
			<div className="flex items-center justify-between p-4 border-b border-vscode-widget-border">
				<div>
					<h1 className="text-2xl font-semibold text-vscode-foreground">
						Plugin Manager
					</h1>
					<p className="text-sm text-vscode-descriptionForeground">
						Manage security plugins for the Web3 Security Platform
					</p>
				</div>
				<div className="flex gap-2">
					{onRefresh && (
						<VSCodeButton appearance="secondary" size="small" onClick={handleRefresh}>
							Refresh
						</VSCodeButton>
					)}
					{showInstalledOnly && (
						<VSCodeButton
							appearance="secondary"
							size="small"
							onClick={() => setFilter({ status: "enabled" })}
						>
							Show Installed Only
						</VSCodeButton>
					)}
				</div>
			</div>

			{/* Filter Bar */}
			<div className="p-4 border-b border-vscode-widget-border">
				<div className="flex gap-3 mb-3">
					{/* Status Filter */}
					<select
						className="bg-vscode-dropdown-background border border-vscode-widget-border rounded-md px-3 py-2 text-vscode-foreground"
						value={filter.status || "all"}
						onChange={(e) =>
							setFilter({ ...filter, status: e.target.value as "all" | "enabled" | "disabled" })
					}
					>
						<option value="all">All</option>
						<option value="enabled">Enabled</option>
						<option value="disabled">Disabled</option>
					</select>

					{/* Search */}
					<div className="flex-1">
						<input
							type="text"
							className="bg-vscode-editor-background border border-vscode-widget-border rounded-md px-3 py-2 text-vscode-foreground flex-1"
							placeholder="Search plugins..."
							value={filter.query || ""}
							onChange={(e) =>
								setFilter({ ...filter, query: e.target.value })
							}
						/>
						<button
							className="bg-vscode-button-background border border-vscode-widget-border rounded-md px-3 py-2 text-vscode-foreground hover:bg-vscode-button-hoverBackground"
							onClick={() => {
								if (filter.query) {
									loadPlugins()
								}
							}}
						>
							Search
						</button>
					</div>

					{/* Refresh Button */}
					<button
						className="bg-vscode-button-background border border-vscode-widget-border rounded-md px-3 py-2 text-vscode-foreground hover:bg-vscode-button-hoverBackground"
						onClick={handleRefresh}
					>
						Refresh
					</button>
				</div>
			</div>

			{/* Stats */}
			<div className="grid grid-cols-3 gap-4 mb-4">
				<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
					<p className="text-sm text-vscode-descriptionForeground mb-1">
						Installed
					</p>
					<p className="text-3xl font-bold text-vscode-foreground">
						{installedCount}
					</p>
				</div>
				<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
					<p className="text-sm text-vscode-descriptionForeground mb-1">
						Enabled
					</p>
					<p className="text-3xl font-bold text-green-500">
						{enabledCount}
					</p>
				</div>
				<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
					<p className="text-sm text-vscode-descriptionForeground mb-1">
						Disabled
					</p>
					<p className="text-3xl font-bold text-gray-400">
						{disabledCount}
					</p>
				</div>
			</div>

			{/* Plugin List */}
			<div className="flex-1 flex-col border-b border-vscode-widget-border">
				<h2 className="text-lg font-semibold mb-3 text-vscode-foreground p-4">
					Plugins ({filteredPlugins.length})
				</h2>
				{loading && (
					<div className="flex items-center justify-center p-8">
						<div className="animate-spin rounded-full h-8 w-8 border-4 border-blue-400 border-t-transparent"></div>
					</div>
				)}

				{!loading && filteredPlugins.length === 0 && (
					<div className="flex flex-col items-center justify-center h-full">
						<div className="text-center p-8">
							<div className="text-6xl mb-4">📦</div>
							<h3 className="text-xl font-semibold text-vscode-foreground mb-2">
								No Plugins Found
							</h3>
							<p className="text-base text-vscode-descriptionForeground">
								Try adjusting your filters or refresh to see available plugins.
							</p>
						</div>
					</div>
				)}

				{!loading && filteredPlugins.length > 0 && (
					<div className="space-y-3">
						{filteredPlugins.map((plugin) => (
							<div
								key={plugin.id}
								className={`bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border cursor-pointer hover:border-vscode-focus-border transition-colors ${
									selectedPlugin === plugin.id ? "border-blue-500" : ""
								}`}
								onClick={() => handleConfigure(plugin.id)}
							>
								{/* Plugin Header */}
								<div className="flex items-start justify-between mb-2">
									<div className="flex items-center gap-2">
										<div className={`w-8 h-8 rounded-full flex items-center justify-center ${getStatusColor(plugin.status)}`}>
											<span className="text-lg">{plugin.name.charAt(0).toUpperCase()}</span>
										</div>
										<div>
											<p className="text-sm text-vscode-descriptionForeground">
												v{plugin.version}
											</p>
										</div>
									</div>
								</div>
								<div className="flex items-center gap-2">
									<span className={`text-sm px-2 py-1 rounded-full ${getStatusColor(plugin.status)}`}>
										{plugin.status.toUpperCase()}
									</span>
								</div>
								<div className="flex items-center gap-2">
									<span className="text-sm text-vscode-descriptionForeground">
										Installed:
									</span>
									<span className="text-base font-medium text-vscode-foreground">
										{plugin.installed ? "Yes" : "No"}
									</span>
								</div>
							</div>

							{/* Quick Actions */}
							<div className="flex gap-2 mt-3">
								{!plugin.installed && (
									<VSCodeButton
										appearance="primary"
										size="small"
										onClick={() => handleInstall(plugin.id)}
									>
										Install
									</VSCodeButton>
								)}
								{plugin.installed && (
									<VSCodeButton
										appearance="secondary"
										size="small"
										onClick={() => handleUninstall(plugin.id)}
									>
										Uninstall
									</VSCodeButton>
								)}
								{plugin.status === "disabled" && (
									<VSCodeButton
										appearance="primary"
										size="small"
										onClick={() => handleEnable(plugin.id)}
									>
										Enable
									</VSCodeButton>
								)}
								{plugin.status === "enabled" && (
									<VSCodeButton
										appearance="secondary"
										size="small"
										onClick={() => handleDisable(plugin.id)}
									>
										Disable
									</VSCodeButton>
								)}
								<VSCodeButton
									appearance="secondary"
									size="small"
									onClick={() => handleUpdate(plugin.id)}
								>
									Update
								</VSCodeButton>
							</div>
						</div>
					))}
				</div>
			)}
		</div>

			{/* Error Message */}
			{error && (
				<div className="p-4 bg-red-50 bg-opacity-10 rounded-lg border border-red-500">
					<p className="text-base font-medium text-red-400">
						Error: {error}
					</p>
				</div>
			)}

			{/* Installing State */}
			{installingId && (
				<div className="flex flex-col items-center justify-center h-full">
					<div className="animate-spin rounded-full h-8 w-8 border-4 border-blue-400 border-t-transparent"></div>
					<p className="text-base text-vscode-descriptionForeground mt-4">
						Installing plugin...
					</p>
					<p className="text-sm font-medium text-vscode-foreground">
						{installingId}
					</p>
				</div>
			)}

			{/* Details Panel */}
			{selectedPlugin && showDetails && (
				<div className="mt-4 p-4 border-b border-vscode-widget-border">
					<div className="flex justify-between items-center mb-2">
						<h2 className="text-lg font-semibold text-vscode-foreground">
							{selectedPlugin.name}
						</h2>
						<VSCodeButton appearance="secondary" size="small" onClick={() => setShowDetails(false)}>
							Close
						</VSCodeButton>
					</div>
					<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
						{/* Plugin Info */}
						<div className="space-y-4">
							<div className="mb-3">
								<p className="text-sm text-vscode-descriptionForeground">
									Version:
								</p>
								<p className="text-base font-medium text-vscode-foreground">
									{selectedPlugin.version}
								</p>
							</div>
							<div className="mb-3">
								<p className="text-sm text-vscode-descriptionForeground">
									Author:
								</p>
								<p className="text-base font-medium text-vscode-foreground">
									{selectedPlugin.author}
								</p>
							</div>
							<div className="mb-3">
								<p className="text-sm text-vscode-descriptionForeground">
									Description:
								</p>
								<p className="text-base font-medium text-vscode-foreground">
									{selectedPlugin.description}
								</p>
							</div>
							<div className="mb-3">
								<p className="text-sm text-vscode-descriptionForeground">
									Status:
								</p>
								<p className={`text-base font-medium ${getStatusColor(selectedPlugin.status)}`}>
									{selectedPlugin.status.toUpperCase()}
								</p>
							</div>
							<div className="mb-3">
								<p className="text-sm text-vscode-descriptionForeground">
									Installed:
								</p>
								<p className="text-base font-medium text-vscode-foreground">
									{selectedPlugin.installed ? "Yes" : "No"}
								</p>
							</div>
							<div className="mb-3">
								<p className="text-sm text-vscode-descriptionForeground">
									Capabilities:
								</p>
								<p className="text-sm font-medium text-vscode-foreground">
									{selectedPlugin.capabilities.join(", ")}
								</p>
							</div>
							<div className="mb-3">
								<p className="text-sm text-vscode-descriptionForeground">
									Supported Chains:
								</p>
								<p className="text-sm font-medium text-vscode-foreground">
									{selectedPlugin.supportedChains.join(", ")}
								</p>
							</div>
						</div>

						{/* Actions */}
						<div className="flex gap-2 mt-4">
							{selectedPlugin.status === "disabled" && (
								<VSCodeButton appearance="primary" onClick={() => handleEnable(selectedPlugin.id)}>
									Enable
								</VSCodeButton>
							)}
							{selectedPlugin.status === "enabled" && (
								<VSCodeButton appearance="secondary" onClick={() => handleDisable(selectedPlugin.id)}>
									Disable
								</VSCodeButton>
							)}
							<VSCodeButton appearance="secondary" onClick={() => handleUpdate(selectedPlugin.id)}>
								Update
								</VSCodeButton>
							<VSCodeButton appearance="secondary" onClick={() => handleUninstall(selectedPlugin.id)}>
									Uninstall
								</VSCodeButton>
						</div>
					</div>
				</div>
			)}
		</div>
	)
}
