import { pgTable, text, timestamp, jsonb, uuid } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const governanceProfilesTable = pgTable("governance_profiles", {
  id: uuid("id").defaultRandom().primaryKey(),
  profile_name: text("profile_name").notNull().unique(),
  description: text("description"),
  phase: text("phase", { enum: ["exploration", "supervised", "autonomous"] }).notNull(),
  allowed_actions: jsonb("allowed_actions"),
  denied_actions: jsonb("denied_actions"),
  constraints: jsonb("constraints"),
  tariff_code: text("tariff_code"),
  created_at: timestamp("created_at").defaultNow().notNull(),
  updated_at: timestamp("updated_at").defaultNow().notNull(),
});

export const insertGovernanceProfileSchema = createInsertSchema(governanceProfilesTable).omit({ id: true });
export type InsertGovernanceProfile = z.infer<typeof insertGovernanceProfileSchema>;
export type GovernanceProfile = typeof governanceProfilesTable.$inferSelect;
