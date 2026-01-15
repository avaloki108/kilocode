import { z } from "zod"

/**
 * Type definitions for Skills Marketplace items
 *
 * These types define the structure of skills data that will be served
 * from the Skills Marketplace API and displayed in the UI.
 */

/**
 * A single skill in the marketplace
 */
export const skillSchema = z.object({
	// Core identity
	id: z.string(),
	description: z.string(),

	// Categorization
	category: z.string(),

	// URLs for viewing/downloading
	githubUrl: z.string(),
	rawUrl: z.string(),
})

export type Skill = z.infer<typeof skillSchema>

/**
 * Container for all skills (the YAML output format from backend)
 */
export const skillsMarketplaceCatalogSchema = z.object({
	items: z.array(skillSchema),
})

export type SkillsMarketplaceCatalog = z.infer<typeof skillsMarketplaceCatalogSchema>
