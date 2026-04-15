import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useHealthCheck, useMandates, usePepHealth } from "@workspace/api-client-react";

export default function DashboardPage() {
  const { data: health } = useHealthCheck();
  const { data: pepHealth } = usePepHealth();
  const { data: mandatesData } = useMandates();

  const mandateList = Array.isArray(mandatesData) ? mandatesData : (mandatesData as Record<string, unknown>)?.mandates as Array<Record<string, unknown>> ?? [];
  const activeCount = mandateList.filter((m) => m.status === "ACTIVE").length;
  const draftCount = mandateList.filter((m) => m.status === "DRAFT").length;
  const revokedCount = mandateList.filter((m) => m.status === "REVOKED").length;

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-muted-foreground mt-1">
          GAuth Governance overview — Power of Attorney compliance monitoring for AI agents.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Total Mandates</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{mandateList.length}</div>
            <p className="text-xs text-muted-foreground mt-1">Across all states</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Active</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-green-600">{activeCount}</div>
            <p className="text-xs text-muted-foreground mt-1">Currently enforcing</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Draft</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-amber-600">{draftCount}</div>
            <p className="text-xs text-muted-foreground mt-1">Pending activation</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Revoked</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-red-600">{revokedCount}</div>
            <p className="text-xs text-muted-foreground mt-1">No longer active</p>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">System Health</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm">API Server</span>
              <Badge variant={health?.status === "ok" ? "default" : "destructive"}>
                {health?.status === "ok" ? "Healthy" : "Unknown"}
              </Badge>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm">PEP Engine</span>
              <Badge variant={pepHealth?.status === "ok" ? "default" : "destructive"}>
                {pepHealth?.status === "ok" ? "Healthy" : "Unknown"}
              </Badge>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm">SDK Version</span>
              <Badge variant="secondary">v0.91.0</Badge>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm">Interface Version</span>
              <Badge variant="secondary">{(pepHealth as Record<string, string>)?.interface_version ?? "—"}</Badge>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Protocol Stack</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {[
              { rfc: "GiFo-RFC 0110", title: "PoA Credential Lifecycle" },
              { rfc: "GiFo-RFC 0111", title: "PEP 16-Check Pipeline" },
              { rfc: "GiFo-RFC 0116", title: "Tariff Model & Adapters" },
              { rfc: "GiFo-RFC 0117", title: "Delegation & Narrowing" },
              { rfc: "GiFo-RFC 0118", title: "Management API" },
            ].map((item) => (
              <div key={item.rfc} className="flex items-center justify-between">
                <div>
                  <span className="text-sm font-medium">{item.rfc}</span>
                  <p className="text-xs text-muted-foreground">{item.title}</p>
                </div>
                <Badge variant="secondary" className="text-xs">Implemented</Badge>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
