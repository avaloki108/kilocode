// kilocode_change - new file

/**
 * Analysis Results Panel Component
 * 
 * This component displays comprehensive analysis results from
 * multiple security tools and agents.
 * 
 * @see WEB3-SECURITY-PLATFORM-ARCHITECTURE.md
 */

import React, { useState } from "react"
import { VSCodeButton } from "@vscode/webview-ui-toolkit/react"

/**
 * Tool result
 */
interface ToolResult {
	tool: string
	status: "success" | "error" | "warning"
	vulnerabilitiesFound: number
	duration: number
	error?: string
}

/**
 * Analysis results panel props
 */
interface AnalysisResultsPanelProps {
	/** Analysis ID */
	analysisId?: string
	/** Tool results */
	toolResults: ToolResult[]
	/** Overall summary */
	summary?: {
		totalVulnerabilities: number
		critical: number
		high: number
		medium: number
		low: number
		informational: number
	}
	/** On export callback */
	onExport?: () => void
	/** On view details callback */
	onViewDetails?: (resultId: string) => void
	/** On retry callback */
	onRetry?: (tool: string) => void
	/** On dismiss callback */
	onDismiss?: () => void
	/** Show full results by default */
	showFullResults?: boolean
}

/**
 * Get status color class
 */
const getStatusColor = (status: string): string => {
	switch (status) {
		case "success":
			return "text-green-500"
		case "error":
			return "text-red-500"
		case "warning":
			return "text-yellow-500"
		default:
			return "text-gray-400"
	}
}

/**
 * Get status icon
 */
const getStatusIcon = (status: string): string => {
	switch (status) {
		case "success":
			return "✅"
		case "error":
			return "❌"
		case "warning":
			return "⚠️"
		default:
			return "⏸️"
	}
}

/**
 * Format duration
 */
const formatDuration = (duration: number): string => {
	if (duration < 60) return `${duration}s`
	if (duration < 3600) return `${Math.floor(duration / 60)}m ${duration % 60}s`
	return `${Math.floor(duration / 3600)}h ${Math.floor((duration % 3600) / 60)}m`
}

/**
 * Analysis Results Panel Component
 */
export const AnalysisResultsPanel: React.FC<AnalysisResultsPanelProps> = ({
	analysisId,
	toolResults,
	summary,
	onExport,
	onViewDetails,
	onRetry,
	onDismiss,
	showFullResults = false,
}) => {
	const [expandedTool, setExpandedTool] = useState<string | null>(null)
	const [selectedResult, setSelectedResult] = useState<string | null>(null)

	// Calculate totals from tool results
	const totalVulnerabilities = toolResults.reduce((sum, result) => sum + result.vulnerabilitiesFound, 0)
	const totalDuration = toolResults.reduce((sum, result) => sum + result.duration, 0)
	const successfulTools = toolResults.filter((r) => r.status === "success").length
	const failedTools = toolResults.filter((r) => r.status === "error").length

	// Toggle tool expansion
	const toggleTool = (toolId: string) => {
		setExpandedTool(expandedTool === toolId ? null : toolId)
		setSelectedResult(null)
	}

	// Select result
	const selectResult = (resultId: string) => {
		setSelectedResult(resultId)
	}

	// Get tool result by ID
	const getToolResult = (toolId: string): ToolResult | undefined => {
		return toolResults.find((r) => r.tool === toolId)
	}

	return (
		<div className="flex flex-col h-full bg-vscode-editor-background">
			{/* Header */}
			<div className="flex items-center justify-between p-4 border-b border-vscode-widget-border">
				<div>
					<h1 className="text-2xl font-semibold text-vscode-foreground">
						Analysis Results
					</h1>
					{analysisId && (
						<p className="text-sm text-vscode-descriptionForeground">
							Analysis ID: {analysisId}
						</p>
					)}
				</div>
				<div className="flex gap-2">
					{onExport && (
						<VSCodeButton appearance="primary" onClick={onExport}>
							Export Report
						</VSCodeButton>
					)}
					{onDismiss && (
						<VSCodeButton appearance="secondary" onClick={onDismiss}>
							Dismiss
						</VSCodeButton>
					)}
				</div>
			</div>

			{/* Summary */}
			{summary && (
				<div className="p-4 border-b border-vscode-widget-border">
					<h2 className="text-lg font-semibold mb-3 text-vscode-foreground">
						Summary
					</h2>
					<div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
						{/* Total Vulnerabilities */}
						<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
							<p className="text-sm text-vscode-descriptionForeground mb-1">
								Total Vulnerabilities
							</p>
							<p className="text-4xl font-bold text-vscode-foreground">
								{summary.totalVulnerabilities}
							</p>
						</div>

						{/* Critical */}
						<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
							<p className="text-sm text-vscode-descriptionForeground mb-1">
								Critical
							</p>
							<p className={`text-4xl font-bold ${getStatusColor(
								summary.critical > 0 ? "error" : "success",
							)}`}>
								{summary.critical}
							</p>
						</div>

						{/* High */}
						<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
							<p className="text-sm text-vscode-descriptionForeground mb-1">
								High
							</p>
							<p className={`text-4xl font-bold ${getStatusColor(
								summary.high > 0 ? "error" : "success",
							)}`}>
								{summary.high}
							</p>
						</div>

						{/* Medium */}
						<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
							<p className="text-sm text-vscode-descriptionForeground mb-1">
								Medium
							</p>
							<p className={`text-4xl font-bold ${getStatusColor(
								summary.medium > 0 ? "error" : "success",
							)}`}>
								{summary.medium}
							</p>
						</div>

						{/* Low */}
						<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
							<p className="text-sm text-vscode-descriptionForeground mb-1">
								Low
							</p>
							<p className={`text-4xl font-bold ${getStatusColor(
								summary.low > 0 ? "error" : "success",
							)}`}>
								{summary.low}
							</p>
						</div>

						{/* Informational */}
						<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
							<p className="text-sm text-vscode-descriptionForeground mb-1">
								Informational
							</p>
							<p className={`text-4xl font-bold ${getStatusColor(
								summary.informational > 0 ? "error" : "success",
							)}`}>
								{summary.informational}
							</p>
						</div>

						{/* Stats */}
						<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
							<p className="text-sm text-vscode-descriptionForeground mb-1">
								Successful Tools
							</p>
							<p className="text-3xl font-bold text-green-500">
								{successfulTools} / {toolResults.length}
							</p>
						</div>
						<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
							<p className="text-sm text-vscode-descriptionForeground mb-1">
								Failed Tools
							</p>
							<p className="text-3xl font-bold text-red-500">
								{failedTools}
							</p>
						</div>
						<div className="bg-vscode-editor-background rounded-lg p-4 border border-vscode-widget-border">
							<p className="text-sm text-vscode-descriptionForeground mb-1">
								Total Duration
							</p>
							<p className="text-3xl font-bold text-vscode-foreground">
								{formatDuration(totalDuration)}
							</p>
						</div>
					</div>
				</div>
			)}

			{/* Tool Results */}
			<div className="flex-1 flex-col border-b border-vscode-widget-border">
				<h2 className="text-lg font-semibold mb-3 text-vscode-foreground p-4">
					Tool Results
				</h2>
				<div className="space-y-3">
					{toolResults.map((result) => {
						const toolResult = getToolResult(result.tool)
						const isExpanded = expandedTool === result.tool

						return (
							<div
								key={result.tool}
								className="bg-vscode-editor-background rounded-lg border border-vscode-widget-border"
							>
								{/* Tool Header */}
								<div
									className="flex items-center justify-between p-3 cursor-pointer"
									onClick={() => toggleTool(result.tool)}
								>
									<div className="flex items-center gap-2">
										<span className="text-lg">{getStatusIcon(result.status)}</span>
										<div>
											<p className="text-sm text-vscode-descriptionForeground">
												{result.tool}
											</p>
											<p className="text-base font-medium text-vscode-foreground">
												{result.vulnerabilitiesFound} vulnerabilities found
											</p>
										</div>
									</div>
									<div className="flex items-center gap-2">
										<span className="text-sm text-vscode-descriptionForeground">
											Duration:
										</span>
										<span className="text-base font-medium text-vscode-foreground">
											{formatDuration(result.duration)}
										</span>
									</div>
									{result.status === "error" && onRetry && (
										<VSCodeButton
											appearance="secondary"
											size="small"
											onClick={() => onRetry(result.tool)}
										>
											Retry
										</VSCodeButton>
									)}
								</div>
							</div>


							{result.status === "error" && result.error && (
								<div className="mt-3 p-3 bg-red-50 bg-opacity-10 rounded border border-red-500">
									<p className="text-sm font-medium text-red-400">
										Error: {result.error}
									</p>
								</div>
							)}

							{/* Success Message */}
							{result.status === "success" && (
								<div className="mt-3 p-3 bg-green-50 bg-opacity-10 rounded border border-green-500">
									<p className="text-sm font-medium text-green-400">
										Analysis completed successfully
									</p>
								</div>
							)}

							{/* View Details Button */}
							{result.status === "success" && onViewDetails && (
								<div className="mt-3">
									<VSCodeButton
										appearance="secondary"
										size="small"
										onClick={() => onViewDetails(result.tool)}
									>
										View Details
									</VSCodeButton>
								</div>
							)}
						</div>
					)}
				</div>
			</div>

			{/* Empty State */}
			{toolResults.length === 0 && (
				<div className="flex flex-col items-center justify-center h-full">
					<div className="text-center p-8">
						<div className="text-6xl mb-4">📊</div>
						<h2 className="text-2xl font-semibold text-vscode-foreground mb-2">
							No Analysis Results
						</h2>
						<p className="text-base text-vscode-descriptionForeground mb-6">
							Start a security analysis to see results from multiple tools and agents.
						</p>
					</div>
				</div>
			)}
		</div>
	)
}
