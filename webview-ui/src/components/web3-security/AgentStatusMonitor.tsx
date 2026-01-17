// kilocode_change - new file

/**
 * Agent Status Monitor Component
 * 
 * This component displays the status of all analysis agents
 * including their current state, progress, and results.
 * 
 * @see WEB3-SECURITY-PLATFORM-ARCHITECTURE.md
 */

import React, { useState, useEffect } from "react"
import { VSCodeButton } from "@vscode/webview-ui-toolkit/react"

/**
 * Agent status
 */
interface AgentStatus {
	id: string
	name: string
	type: string
	status: "idle" | "running" | "completed" | "error"
	progress: number
	vulnerabilitiesFound: number
	lastActivity: number
}

/**
 * Agent status monitor props
 */
interface AgentStatusMonitorProps {
	/** List of agent statuses */
	agents: AgentStatus[]
	/** Auto-refresh interval in milliseconds */
	refreshInterval?: number
	/** On agent click callback */
	onAgentClick?: (agentId: string) => void
	/** On refresh callback */
	onRefresh?: () => void
}

/**
 * Get status color class
 */
const getStatusColor = (status: string): string => {
	switch (status) {
		case "idle":
			return "text-gray-400"
		case "running":
			return "text-blue-400"
		case "completed":
			return "text-green-500"
		case "error":
			return "text-red-500"
		default:
			return "text-gray-400"
	}
}

/**
 * Get status icon
 */
const getStatusIcon = (status: string): string => {
	switch (status) {
		case "idle":
			return "⏸️"
		case "running":
			return "🔄"
		case "completed":
			return "✅"
		case "error":
			return "❌"
		default:
			return "⏸️"
	}
}

/**
 * Agent Status Monitor Component
 */
export const AgentStatusMonitor: React.FC<AgentStatusMonitorProps> = ({
	agents,
	refreshInterval = 5000,
	onAgentClick,
	onRefresh,
}) => {
	const [currentTime, setCurrentTime] = useState(new Date())

	// Update current time every second
	useEffect(() => {
		const interval = setInterval(() => {
			setCurrentTime(new Date())
		}, 1000)

		return () => clearInterval(interval)
	}, [])

	// Auto-refresh
	useEffect(() => {
		if (!refreshInterval || refreshInterval < 1000) {
			return
		}

		const interval = setInterval(() => {
			// Trigger refresh callback
			if (onRefresh) {
				onRefresh()
			}
		}, refreshInterval)

		return () => clearInterval(interval)
	}, [refreshInterval])

	// Get active agents count
	const activeAgentsCount = agents.filter((a) => a.status === "running").length
	const completedAgentsCount = agents.filter((a) => a.status === "completed").length
	const totalVulnerabilities = agents.reduce((sum, a) => sum + a.vulnerabilitiesFound, 0)

	return (
		<div className="flex flex-col h-full bg-vscode-editor-background">
			{/* Header */}
			<div className="flex items-center justify-between p-4 border-b border-vscode-widget-border">
				<div>
					<h1 className="text-xl font-semibold text-vscode-foreground">
						Agent Status Monitor
					</h1>
					<p className="text-sm text-vscode-descriptionForeground">
						{currentTime.toLocaleString()}
					</p>
				</div>
				<div className="flex gap-2">
					{onRefresh && (
						<VSCodeButton appearance="secondary" size="small" onClick={onRefresh}>
							Refresh
						</VSCodeButton>
					)}
				</div>
			</div>

			{/* Summary Stats */}
			<div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
				{/* Total Agents */}
				<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
					<p className="text-sm text-vscode-descriptionForeground mb-1">
						Total Agents
					</p>
					<p className="text-3xl font-bold text-vscode-foreground">
						{agents.length}
					</p>
				</div>

				{/* Active Agents */}
				<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
					<p className="text-sm text-vscode-descriptionForeground mb-1">
						Active
					</p>
					<p className={`text-3xl font-bold ${getStatusColor("running")}`}>
						{activeAgentsCount}
					</p>
				</div>

				{/* Completed */}
				<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
					<p className="text-sm text-vscode-descriptionForeground mb-1">
						Completed
					</p>
					<p className={`text-3xl font-bold ${getStatusColor("completed")}`}>
						{completedAgentsCount}
					</p>
				</div>

				{/* Total Vulnerabilities */}
				<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
					<p className="text-sm text-vscode-descriptionForeground mb-1">
						Total Vulnerabilities
					</p>
					<p className="text-3xl font-bold text-vscode-foreground">
						{totalVulnerabilities}
					</p>
				</div>

				{/* Errors */}
				<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
					<p className="text-sm text-vscode-descriptionForeground mb-1">
						Errors
					</p>
					<p className="text-3xl font-bold text-red-500">
						{agents.filter((a) => a.status === "error").length}
					</p>
				</div>
			</div>

			{/* Agent List */}
			<div className="flex-1 flex-col border-b border-vscode-widget-border">
				<h2 className="text-lg font-semibold mb-3 text-vscode-foreground p-4">
					Agents
				</h2>
				<div className="space-y-2">
					{agents.map((agent) => (
						<div
							key={agent.id}
							className={`bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border cursor-pointer hover:border-vscode-focus-border transition-colors ${agent.status === "running" ? "animate-pulse" : ""}`}
							onClick={() => onAgentClick?.(agent.id)}
						>
							<div className="flex items-start gap-3">
								{/* Status Icon */}
								<div className="flex-shrink-0">
									<div className={`w-8 h-8 rounded-full flex items-center justify-center ${getStatusColor(agent.status)}`}>
										<span className="text-lg">{getStatusIcon(agent.status)}</span>
									</div>
								</div>

								{/* Agent Info */}
								<div className="flex-1">
									<div>
										<p className="text-sm text-vscode-descriptionForeground">
											Name:
										</p>
										<p className="text-base font-medium text-vscode-foreground">
											{agent.name}
										</p>
									</div>
									<div>
										<p className="text-sm text-vscode-descriptionForeground">
											Type:
										</p>
										<p className="text-sm font-medium text-vscode-foreground">
											{agent.type}
										</p>
									</div>
								</div>
							</div>

							{/* Progress & Stats */}
							<div className="flex-1 space-y-2">
								{agent.status === "running" && (
								<>
										<div className="flex items-center gap-2 mb-1">
											<span className="text-sm text-vscode-descriptionForeground">
												Progress:
											</span>
											<div className="w-full bg-vscode-progressBar-background rounded-full h-2">
												<div
													className="bg-vscode-progressBar-foreground h-full rounded-full transition-all duration-300"
													style={{ width: `${agent.progress}%` }}
												/>
											</div>
											<span className="text-sm font-medium text-vscode-foreground">
												{agent.progress}%
											</span>
										</div>
									</div>
									<div className="flex items-center gap-2">
										<span className="text-sm text-vscode-descriptionForeground">
											Vulnerabilities Found:
										</span>
										<span className="text-base font-medium text-vscode-foreground">
											{agent.vulnerabilitiesFound}
										</span>
									</div>
							</>
						)}
										<span className="text-sm text-vscode-descriptionForeground">
											Completed:
										</span>
										<span className="text-sm font-medium text-vscode-foreground">
											{agent.vulnerabilitiesFound} vulnerabilities
										</span>
									</div>
								)}

								{agent.status === "error" && (
									<div className="flex items-center gap-2">
										<span className="text-sm text-red-400">
											Error
										</span>
										<span className="text-sm font-medium text-vscode-foreground">
											See details
										</span>
									</div>
								)}

								{/* Last Activity */}
								<div className="text-sm text-vscode-descriptionForeground">
									Last Activity:
								</div>
								<p className="text-sm font-medium text-vscode-foreground">
									{new Date(agent.lastActivity).toLocaleString()}
								</p>
							</div>
						</div>
					))}
				</div>
			</div>

			{/* Empty State */}
			{agents.length === 0 && (
				<div className="flex flex-col items-center justify-center h-full">
					<div className="text-center p-8">
						<div className="text-6xl mb-4">🤖</div>
						<h2 className="text-2xl font-semibold text-vscode-foreground mb-2">
							No Agents Active
						</h2>
						<p className="text-base text-vscode-descriptionForeground mb-6">
							No analysis agents are currently running. Start an analysis or enable monitoring to see agent status.
						</p>
					</div>
				</div>
			)}
		</div>
	)
}
