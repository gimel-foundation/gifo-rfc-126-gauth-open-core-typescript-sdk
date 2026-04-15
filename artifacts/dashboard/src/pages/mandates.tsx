import { Link } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useMandates } from "@workspace/api-client-react";

const STATUS_COLORS: Record<string, string> = {
  ACTIVE: "bg-green-100 text-green-800",
  DRAFT: "bg-amber-100 text-amber-800",
  SUSPENDED: "bg-orange-100 text-orange-800",
  REVOKED: "bg-red-100 text-red-800",
  EXPIRED: "bg-gray-100 text-gray-800",
  PENDING_APPROVAL: "bg-blue-100 text-blue-800",
};

export default function MandatesPage() {
  const { data: mandatesData, isLoading, error } = useMandates();

  const mandateList = Array.isArray(mandatesData) ? mandatesData : (mandatesData as Record<string, unknown>)?.mandates as typeof mandatesData ?? [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Mandates</h1>
          <p className="text-muted-foreground mt-1">
            Manage Power of Attorney mandates for AI agents.
          </p>
        </div>
        <Button>Create Mandate</Button>
      </div>

      {isLoading && (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            Loading mandates...
          </CardContent>
        </Card>
      )}

      {error && (
        <Card>
          <CardContent className="py-12 text-center text-red-600">
            Failed to load mandates. The API server may not be running.
          </CardContent>
        </Card>
      )}

      {!isLoading && !error && mandateList.length === 0 && (
        <Card>
          <CardContent className="py-12 text-center">
            <p className="text-muted-foreground">No mandates found.</p>
            <p className="text-sm text-muted-foreground mt-1">
              Create your first mandate using the Management API or the button above.
            </p>
          </CardContent>
        </Card>
      )}

      {mandateList.length > 0 && (
        <div className="space-y-3">
          {mandateList.map((mandate) => (
            <Link key={mandate.mandate_id} href={`/mandates/${mandate.mandate_id}`}>
              <Card className="cursor-pointer hover:shadow-md transition-shadow">
                <CardContent className="py-4">
                  <div className="flex items-center justify-between">
                    <div className="space-y-1">
                      <div className="flex items-center gap-3">
                        <span className="font-mono text-sm font-medium">
                          {mandate.mandate_id}
                        </span>
                        <Badge className={STATUS_COLORS[mandate.status] ?? ""}>
                          {mandate.status}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-4 text-sm text-muted-foreground">
                        <span>Agent: {mandate.subject_agent_id}</span>
                        <span>Profile: {mandate.governance_profile}</span>
                        <span>Phase: {mandate.phase}</span>
                      </div>
                    </div>
                    <div className="text-sm text-muted-foreground">
                      {new Date(mandate.created_at).toLocaleDateString()}
                    </div>
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
