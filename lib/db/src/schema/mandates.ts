import { pgTable, text, timestamp, integer, jsonb, uuid } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const mandatesTable = pgTable("mandates", {
  id: uuid("id").defaultRandom().primaryKey(),
  mandate_id: text("mandate_id").notNull().unique(),
  status: text("status", { enum: ["DRAFT", "ACTIVE", "SUSPENDED", "REVOKED", "EXPIRED", "PENDING_APPROVAL"] }).notNull().default("DRAFT"),
  issuer: text("issuer").notNull(),
  subject_agent_id: text("subject_agent_id").notNull(),
  governance_profile: text("governance_profile").notNull(),
  phase: text("phase", { enum: ["exploration", "supervised", "autonomous"] }).notNull(),
  scope: jsonb("scope"),
  constraints: jsonb("constraints"),
  budget_cents: integer("budget_cents"),
  budget_spent_cents: integer("budget_spent_cents").default(0),
  ttl_seconds: integer("ttl_seconds"),
  max_delegation_depth: integer("max_delegation_depth").default(0),
  parent_mandate_id: text("parent_mandate_id"),
  delegation_depth: integer("delegation_depth").default(0),
  approval_mode: text("approval_mode", { enum: ["auto", "supervised", "four_eyes"] }).default("auto"),
  created_by: text("created_by").notNull(),
  activated_by: text("activated_by"),
  revoked_by: text("revoked_by"),
  revocation_reason: text("revocation_reason"),
  created_at: timestamp("created_at").defaultNow().notNull(),
  activated_at: timestamp("activated_at"),
  expires_at: timestamp("expires_at"),
  updated_at: timestamp("updated_at").defaultNow().notNull(),
});

export const insertMandateSchema = createInsertSchema(mandatesTable).omit({ id: true });
export type InsertMandate = z.infer<typeof insertMandateSchema>;
export type Mandate = typeof mandatesTable.$inferSelect;
