import { pgTable, text, timestamp, jsonb, uuid, integer } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const auditLogsTable = pgTable("audit_logs", {
  id: uuid("id").defaultRandom().primaryKey(),
  event_type: text("event_type").notNull(),
  mandate_id: text("mandate_id"),
  agent_id: text("agent_id"),
  action: text("action"),
  decision: text("decision", { enum: ["ALLOW", "DENY", "ABSTAIN"] }),
  violation_code: text("violation_code"),
  detail: text("detail"),
  slot_name: text("slot_name"),
  check_results: jsonb("check_results"),
  processing_time_ms: integer("processing_time_ms"),
  performed_by: text("performed_by"),
  ip_address: text("ip_address"),
  created_at: timestamp("created_at").defaultNow().notNull(),
});

export const insertAuditLogSchema = createInsertSchema(auditLogsTable).omit({ id: true });
export type InsertAuditLog = z.infer<typeof insertAuditLogSchema>;
export type AuditLog = typeof auditLogsTable.$inferSelect;
