import { pgTable, text, timestamp, jsonb, uuid, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const credentialsTable = pgTable("credentials", {
  id: uuid("id").defaultRandom().primaryKey(),
  credential_id: text("credential_id").notNull().unique(),
  mandate_id: text("mandate_id").notNull(),
  type: text("type", { enum: ["PoACredential", "VerifiableCredential", "VerifiablePresentation"] }).notNull(),
  issuer_did: text("issuer_did"),
  subject_did: text("subject_did"),
  credential_data: jsonb("credential_data").notNull(),
  proof: jsonb("proof"),
  status: text("status", { enum: ["VALID", "REVOKED", "SUSPENDED", "EXPIRED"] }).notNull().default("VALID"),
  revoked: boolean("revoked").default(false),
  revocation_reason: text("revocation_reason"),
  issued_at: timestamp("issued_at").defaultNow().notNull(),
  expires_at: timestamp("expires_at"),
  created_at: timestamp("created_at").defaultNow().notNull(),
});

export const insertCredentialSchema = createInsertSchema(credentialsTable).omit({ id: true });
export type InsertCredential = z.infer<typeof insertCredentialSchema>;
export type Credential = typeof credentialsTable.$inferSelect;
