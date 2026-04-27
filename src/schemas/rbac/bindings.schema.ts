import { z } from 'zod'

/**
 * Bindings file schema - User to group assignments
 *
 * NOTE: Groups are now stored in a separate groups.json file.
 * This file only contains user-to-group mappings.
 *
 * Structure:
 * {
 *   "emails": {},                          // Reserved for future use
 *   "group_membership": {                  // User → groups assignment
 *     "user@w6d.io": ["super_admins"],
 *     "other@w6d.io": ["admins", "devs"]
 *   }
 * }
 */

/**
 * User membership entry - can be simple array or object with metadata
 */
export const userMembershipSchema = z.union([
  // Simple format: ["group1", "group2"]
  z.array(z.string()),
  // Extended format with metadata
  z.object({
    groups: z.array(z.string()),
    addedAt: z.string().datetime().optional(),
    addedBy: z.string().email().optional(),
  }),
])

/**
 * Group membership: email → groups (or extended object)
 */
export const groupMembershipSchema = z.record(
  z.string(),
  userMembershipSchema
)

/**
 * Main bindings file schema
 * NOTE: groups are now in a separate groups.json file
 */
export const bindingsFileSchema = z.object({
  emails: z.record(z.string(), z.unknown()).default({}),
  group_membership: groupMembershipSchema,
})

// Type exports
export type UserMembership = z.infer<typeof userMembershipSchema>
export type GroupMembership = z.infer<typeof groupMembershipSchema>
export type BindingsFile = z.infer<typeof bindingsFileSchema>

/**
 * Helper to get groups array from membership entry
 */
export function getUserGroups(membership: UserMembership): string[] {
  if (Array.isArray(membership)) {
    return membership
  }
  return membership.groups
}

/**
 * Helper to create extended membership entry
 */
export function createMembershipEntry(
  groups: string[],
  addedBy?: string
): { groups: string[]; addedAt: string; addedBy?: string } {
  return {
    groups,
    addedAt: new Date().toISOString(),
    addedBy,
  }
}

// JSON Schema for OpenAPI
export const bindingsFileJsonSchema = {
  type: 'object',
  properties: {
    emails: {
      type: 'object',
      description: 'Reserved for future use',
      additionalProperties: true,
    },
    group_membership: {
      type: 'object',
      description: 'User group assignments: email → groups[] or { groups, addedAt, addedBy }',
      additionalProperties: {
        oneOf: [
          {
            type: 'array',
            items: { type: 'string' },
          },
          {
            type: 'object',
            properties: {
              groups: { type: 'array', items: { type: 'string' } },
              addedAt: { type: 'string', format: 'date-time' },
              addedBy: { type: 'string', format: 'email' },
            },
            required: ['groups'],
          },
        ],
      },
    },
  },
  required: ['group_membership'],
}
