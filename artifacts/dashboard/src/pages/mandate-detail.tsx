import { useParams, Link } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { useMandate } from "@workspace/api-client-react";

export default function MandateDetailPage() {
  const params = useParams<{ id: string }>();
  const mandateId = params.id ?? "";
  const { data: mandate, isLoading, error } = useMandate(mandateId);

  if (isLoading) {
    return (
      <div className="py-12 text-center text-muted-foreground">Loading mandate...</div>
    );
  }

  if (error || !mandate) {
    return (
      <div className="space-y-4">
        <Link href="/mandates">
          <Button variant="ghost" size="sm">&larr; Back to Mandates</Button>
        </Link>
        <Card>
          <CardContent className="py-12 text-center text-red-600">
            Mandate not found or failed to load.
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link href="/mandates">
            <Button variant="ghost" size="sm">&larr; Back</Button>
          </Link>
          <div>
            <h1 className="text-xl font-bold tracking-tight font-mono">{mandate.mandate_id}</h1>
            <p className="text-sm text-muted-foreground">Mandate Detail</p>
          </div>
        </div>
        <Badge
          className={
            mandate.status === "ACTIVE" ? "bg-green-100 text-green-800"
            : mandate.status === "DRAFT" ? "bg-amber-100 text-amber-800"
            : mandate.status === "REVOKED" ? "bg-red-100 text-red-800"
            : ""
          }
        >
          {mandate.status}
        </Badge>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Identity</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <InfoRow label="Issuer" value={mandate.issuer} />
            <InfoRow label="Agent ID" value={mandate.subject_agent_id} />
            <InfoRow label="Governance Profile" value={mandate.governance_profile} />
            <InfoRow label="Phase" value={mandate.phase} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Lifecycle</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <InfoRow label="Created" value={new Date(mandate.created_at).toLocaleString()} />
            <InfoRow label="Activated" value={mandate.activated_at ? new Date(mandate.activated_at).toLocaleString() : "—"} />
            <InfoRow label="Expires" value={mandate.expires_at ? new Date(mandate.expires_at).toLocaleString() : "No expiry"} />
            <InfoRow label="TTL (seconds)" value={mandate.ttl_seconds?.toString() ?? "—"} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Budget</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <InfoRow label="Budget" value={mandate.budget_cents != null ? `$${(mandate.budget_cents / 100).toFixed(2)}` : "Unlimited"} />
            <InfoRow label="Spent" value={mandate.budget_spent_cents != null ? `$${(mandate.budget_spent_cents / 100).toFixed(2)}` : "$0.00"} />
            {mandate.budget_cents != null && (
              <div className="mt-2">
                <div className="w-full bg-muted rounded-full h-2">
                  <div
                    className="bg-primary rounded-full h-2 transition-all"
                    style={{ width: `${Math.min(100, ((mandate.budget_spent_cents ?? 0) / mandate.budget_cents) * 100)}%` }}
                  />
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Delegation</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <InfoRow label="Max Depth" value={mandate.max_delegation_depth?.toString() ?? "0"} />
            <InfoRow label="Current Depth" value={mandate.delegation_depth?.toString() ?? "0"} />
            <InfoRow label="Parent Mandate" value={mandate.parent_mandate_id ?? "Root (no parent)"} />
          </CardContent>
        </Card>
      </div>

      {(mandate.scope || mandate.constraints) && (
        <>
          <Separator />
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {mandate.scope && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Scope</CardTitle>
                </CardHeader>
                <CardContent>
                  <pre className="text-xs bg-muted p-4 rounded-lg overflow-auto max-h-64 font-mono">
                    {JSON.stringify(mandate.scope, null, 2)}
                  </pre>
                </CardContent>
              </Card>
            )}
            {mandate.constraints && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Constraints</CardTitle>
                </CardHeader>
                <CardContent>
                  <pre className="text-xs bg-muted p-4 rounded-lg overflow-auto max-h-64 font-mono">
                    {JSON.stringify(mandate.constraints, null, 2)}
                  </pre>
                </CardContent>
              </Card>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-sm text-muted-foreground">{label}</span>
      <span className="text-sm font-medium">{value}</span>
    </div>
  );
}
