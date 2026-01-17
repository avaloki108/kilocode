// kilocode_change - new file

/**
 * Security Dashboard Component
 * 
 * This is the main dashboard component for the Web3 Security Platform.
 * It provides an overview of security analysis status, vulnerabilities,
 * and active monitoring.
 * 
 * @see WEB3-SECURITY-PLATFORM-ARCHITECTURE.md
 */

import React, { useState, useEffect } from "react"
import { VSCodeButton } from "@vscode/webview-ui-toolkit/react"

/**
 * Vulnerability summary statistics
 */
interface VulnerabilitySummary {
	total: number
	critical: number
	high: number
	medium: number
	low: number
	informational: number
}

/**
 * Analysis status
 */
interface AnalysisStatus {
	id: string
	contract: string
	status: "idle" | "analyzing" | "completed" | "failed"
	progress: number
	startTime?: number
	endTime?: number
}

/**
 * Active monitoring info
 */
interface ActiveMonitoring {
	contract: string
	chain: string
	status: "monitoring" | "paused" | "error"
	eventsDetected: number
}

/**
 * Security dashboard props
 */
interface SecurityDashboardProps {
	/** Current analysis status */
	analysisStatus?: AnalysisStatus
	/** Vulnerability summary */
	vulnerabilitySummary?: VulnerabilitySummary
	/** Active monitoring */
	activeMonitoring?: ActiveMonitoring[]
	/** On refresh callback */
	onRefresh?: () => void
	/** On analyze callback */
	onAnalyze?: () => void
	/** On view report callback */
	onViewReport?: () => void
	/** On manage plugins callback */
	onManagePlugins?: () => void
}

/**
 * Security Dashboard Component
 */
export const SecurityDashboard: React.FC<SecurityDashboardProps> = ({
	analysisStatus,
	vulnerabilitySummary,
	activeMonitoring,
	onRefresh,
	onAnalyze,
	onViewReport,
	onManagePlugins,
}) => {
	const [currentTime, setCurrentTime] = useState(new Date())

	// Update current time every second
	useEffect(() => {
		const interval = setInterval(() => {
			setCurrentTime(new Date())
		}, 1000)

		return () => clearInterval(interval)
	}, [])

	// Get severity color class
	const getSeverityColor = (severity: string): string => {
		switch (severity) {
			case "critical":
				return "text-red-500"
			case "high":
				return "text-orange-500"
			case "medium":
				return "text-yellow-500"
			case "low":
				return "text-blue-500"
			default:
				return "text-gray-500"
		}
	}

	// Get status color class
	const getStatusColor = (status: string): string => {
		switch (status) {
			case "analyzing":
				return "text-blue-400"
			case "completed":
				return "text-green-500"
			case "failed":
				return "text-red-500"
			default:
				return "text-gray-400"
		}
	}

	// Get monitoring status color
	const getMonitoringStatusColor = (status: string): string => {
		switch (status) {
			case "monitoring":
				return "text-green-500"
			case "paused":
				return "text-yellow-500"
			case "error":
				return "text-red-500"
			default:
				return "text-gray-400"
		}
	}

	// Format time
	const formatTime = (date?: Date): string => {
		if (!date) return "--"
		return new Date(date).toLocaleTimeString()
	}

	// Format duration
	const formatDuration = (start?: number, end?: number): string => {
		if (!start || !end) return "--"
		const duration = Math.floor((end - start) / 1000)
		if (duration < 60) return `${duration}s`
		if (duration < 3600) return `${Math.floor(duration / 60)}m ${duration % 60}s`
		return `${Math.floor(duration / 3600)}h ${Math.floor((duration % 3600) / 60)}m`
	}

	return (
		<div className="flex flex-col h-full bg-vscode-editor-background">
			{/* Header */}
			<div className="flex items-center justify-between p-4 border-b border-vscode-widget-border">
				<div>
					<h1 className="text-2xl font-semibold text-vscode-foreground">
						Web3 Security Dashboard
					</h1>
					<p className="text-sm text-vscode-descriptionForeground">
						{currentTime.toLocaleString()}
					</p>
				</div>
				<div className="flex gap-2">
					{onRefresh && (
						<VSCodeButton appearance="secondary" onClick={onRefresh}>
							Refresh
						</VSCodeButton>
					)}
					{onAnalyze && (
						<VSCodeButton appearance="primary" onClick={onAnalyze}>
							Analyze
						</VSCodeButton>
					)}
					{onViewReport && (
						<VSCodeButton appearance="secondary" onClick={onViewReport}>
							View Report
						</VSCodeButton>
					)}
					{onManagePlugins && (
						<VSCodeButton appearance="secondary" onClick={onManagePlugins}>
							Plugins
						</VSCodeButton>
					)}
				</div>
			</div>

			{/* Analysis Status */}
			{analysisStatus && (
				<div className="p-4 border-b border-vscode-widget-border">
					<h2 className="text-lg font-semibold mb-3 text-vscode-foreground">
						Analysis Status
					</h2>
					<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
						<div className="flex items-center justify-between mb-2">
							<div>
								<p className="text-sm text-vscode-descriptionForeground">
									Contract:
								</p>
								<p className="text-base font-medium text-vscode-foreground">
									{analysisStatus.contract}
								</p>
							</div>
							<div className={`text-sm font-medium ${getStatusColor(analysisStatus.status)}`}>
								{analysisStatus.status.toUpperCase()}
							</div>
						</div>
						{analysisStatus.status === "analyzing" && (
							<div className="mb-4">
								<div className="flex justify-between mb-1">
									<span className="text-sm text-vscode-descriptionForeground">
										Progress:
									</span>
									<span className="text-base font-medium text-vscode-foreground">
										{analysisStatus.progress}%
									</span>
								</div>
								<div className="w-full bg-vscode-progressBar-background rounded-full h-2">
									<div
										className="bg-vscode-progressBar-foreground h-full rounded-full transition-all duration-300"
										style={{ width: `${analysisStatus.progress}%` }}
									/>
								</div>
								<div className="flex justify-between text-sm text-vscode-descriptionForeground">
									<span>Started: {formatTime(analysisStatus.startTime)}</span>
									<span>Duration: {formatDuration(analysisStatus.startTime, Date.now())}</span>
								</div>
							</div>
						)}
						{analysisStatus.status === "completed" && (
							<div className="text-sm text-vscode-descriptionForeground">
								<p className="mb-1">
									<span className="text-green-500 font-medium">Completed</span>
									<span> at {formatTime(analysisStatus.endTime)}</span>
								</p>
								<p>
									Total Duration: {formatDuration(analysisStatus.startTime, analysisStatus.endTime)}
								</p>
							</div>
						)}
						{analysisStatus.status === "failed" && (
							<div className="text-sm text-red-400">
								<p className="mb-1">
									<span className="font-medium">Failed</span>
									<span> at {formatTime(analysisStatus.endTime)}</span>
								</p>
								<p>Check the console for more details.</p>
							</div>
						)}
					</div>
				</div>
			)}

			{/* Vulnerability Summary */}
			{vulnerabilitySummary && (
				<div className="p-4 border-b border-vscode-widget-border">
					<h2 className="text-lg font-semibold mb-3 text-vscode-foreground">
						Vulnerability Summary
					</h2>
					<div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
						{/* Total */}
						<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
							<p className="text-sm text-vscode-descriptionForeground mb-1">
								Total
							</p>
							<p className="text-3xl font-bold text-vscode-foreground">
								{vulnerabilitySummary.total}
							</p>
						</div>

						{/* Critical */}
						<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
							<p className="text-sm text-vscode-descriptionForeground mb-1">
								Critical
							</p>
							<p className={`text-3xl font-bold ${getSeverityColor("critical")}`}>
								{vulnerabilitySummary.critical}
							</p>
						</div>

						{/* High */}
						<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
							<p className="text-sm text-vscode-descriptionForeground mb-1">
								High
							</p>
							<p className={`text-3xl font-bold ${getSeverityColor("high")}`}>
								{vulnerabilitySummary.high}
							</p>
						</div>

						{/* Medium */}
						<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
							<p className="text-sm text-vscode-descriptionForeground mb-1">
								Medium
							</p>
							<p className={`text-3xl font-bold ${getSeverityColor("medium")}`}>
								{vulnerabilitySummary.medium}
							</p>
						</div>

						{/* Low */}
						<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
							<p className="text-sm text-vscode-descriptionForeground mb-1">
								Low
							</p>
							<p className={`text-3xl font-bold ${getSeverityColor("low")}`}>
								{vulnerabilitySummary.low}
							</p>
						</div>

						{/* Informational */}
						<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
							<p className="text-sm text-vscode-descriptionForeground mb-1">
								Informational
							</p>
							<p className={`text-3xl font-bold ${getSeverityColor("informational")}`}>
								{vulnerabilitySummary.informational}
							</p>
						</div>
					</div>
				</div>
			)}

			{/* Active Monitoring */}
			{activeMonitoring && activeMonitoring.length > 0 && (
				<div className="p-4 border-b border-vscode-widget-border">
					<h2 className="text-lg font-semibold mb-3 text-vscode-foreground">
						Active Monitoring
					</h2>
					<div className="space-y-3">
						{activeMonitoring.map((monitoring, index) => (
							<div
								key={index}
								className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border"
							>
								<div className="flex items-center justify-between mb-2">
									<div>
										<p className="text-sm text-vscode-descriptionForeground">
											Contract:
										</p>
										<p className="text-base font-medium text-vscode-foreground">
											{monitoring.contract}
										</p>
									</div>
									<div className="flex items-center gap-2">
										<div className="text-sm text-vscode-descriptionForeground">
											<span>Chain:</span>
											<span className="text-base font-medium text-vscode-foreground">
												{monitoring.chain}
											</span>
										</div>
										<div
											className={`text-sm font-medium px-3 py-1 rounded-full ${getMonitoringStatusColor(
												monitoring.status,
											)}`}
										>
											{monitoring.status.toUpperCase()}
										</div>
									</div>
								</div>
								<div className="flex items-center justify-between">
									<div className="text-sm text-vscode-descriptionForeground">
										Events Detected:
									</div>
									<div className="text-3xl font-bold text-vscode-foreground">
										{monitoring.eventsDetected}
									</div>
								</div>
							</div>
						))}
					</div>
				)}

			{/* Empty State */}
			{!analysisStatus && !vulnerabilitySummary && (!activeMonitoring || activeMonitoring.length === 0) && (
				<div className="flex flex-col items-center justify-center h-full">
					<div className="text-center p-8">
						<div className="text-6xl mb-4">🔒</div>
						<h2 className="text-2xl font-semibold text-vscode-foreground mb-2">
							No Active Analysis
						</h2>
						<p className="text-base text-vscode-descriptionForeground mb-6">
							Start a security analysis or enable monitoring to see vulnerabilities and
							security insights.
						</p>
						<div className="flex gap-3 justify-center">
							{onAnalyze && (
								<VSCodeButton appearance="primary" onClick={onAnalyze}>
									Start Analysis
								</VSCodeButton>
							)}
							{onManagePlugins && (
								<VSCodeButton appearance="secondary" onClick={onManagePlugins}>
									Manage Plugins
								</VSCodeButton>
							)}
						</div>
					</div>
				</div>
			)}
		</div>
	)
}
