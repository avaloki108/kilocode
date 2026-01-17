// kilocode_change - new file
import { z } from "zod"

/**
 * Plugin state
 */
export const pluginStateSchema = z.enum(["installed", "enabled", "disabled", "error"])

export type PluginState = z.infer<typeof pluginStateSchema>

/**
 * Plugin capability
 */
export const pluginCapabilitySchema = z.object({
	vulnerabilityTypes: z.array(
		z.enum([
			"reentrancy",
			"arithmetic",
			"access_control",
			"front_running",
			"logic_error",
			"gas_issue",
			"storage",
			"delegatecall",
			"timestamp",
			"tx_origin",
			"oracle_manipulation",
			"logic_flaw",
		]),
	),
	supportedChains: z.array(z.enum(["evm", "solana", "cosmos", "polkadot", "near", "aptos", "sui", "movr"])),
	analysisMethods: z.array(z.enum(["static", "dynamic", "symbolic", "fuzzing", "formal_verification"])),
})

export type PluginCapability = z.infer<typeof pluginCapabilitySchema>

/**
 * Security plugin interface schema
 */
export const securityPluginSchema = z.object({
	name: z.string().min(1),
	version: z.string().regex(/^\d+\.\d+\.\d+$/),
	description: z.string().optional(),
	author: z.string().optional(),
	homepage: z.string().url().optional(),
	repository: z.string().url().optional(),
	capabilities: pluginCapabilitySchema,
	enabled: z.boolean().default(true),
	priority: z.number().min(0).max(100).default(50),
	config: z.record(z.string(), z.unknown()).optional(),
})

export type SecurityPlugin = z.infer<typeof securityPluginSchema>

/**
 * Plugin manifest schema
 */
export const pluginManifestSchema = z.object({
	name: z.string(),
	version: z.string(),
	description: z.string(),
	author: z.string(),
	license: z.string(),
	homepage: z.string().url().optional(),
	repository: z.string().url(),
	main: z.string(),
	capabilities: pluginCapabilitySchema,
	keywords: z.array(z.string()),
	supportedKilocodeVersions: z.array(z.string()),
})

export type PluginManifest = z.infer<typeof pluginManifestSchema>

/**
 * Plugin marketplace item
 */
export const marketplacePluginSchema = z.object({
	id: z.string(),
	name: z.string(),
	version: z.string(),
	description: z.string(),
	author: z.string(),
	homepage: z.string().url().optional(),
	repository: z.string().url(),
	downloads: z.number().optional(),
	rating: z.number().min(0).max(5).optional(),
	lastUpdated: z.string().optional(),
	tags: z.array(z.string()),
	capabilities: pluginCapabilitySchema,
	verified: z.boolean().default(false),
})

export type MarketplacePlugin = z.infer<typeof marketplacePluginSchema>
