import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { usePoaMap, useMandates } from "@workspace/api-client-react";

export default function PoaMapPage() {
  const { data: poaMap, isLoading: mapLoading } = usePoaMap();
  const { data: mandatesData } = useMandates();

  const mandateList = Array.isArray(mandatesData) ? mandatesData : (mandatesData as Record<string, unknown>)?.mandates as Array<Record<string, unknown>> ?? [];
  const mapEntries = Array.isArray(poaMap) ? poaMap : [];

  const rootMandates = mandateList.filter((m) => !m.parent_mandate_id);
  const delegations = mandateList.filter((m) => m.parent_mandate_id);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Power of Attorney Map</h1>
        <p className="text-muted-foreground mt-1">
          Visualization of the mandate delegation hierarchy and PoA credential chain.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-3xl font-bold">{rootMandates.length}</div>
              <p className="text-sm text-muted-foreground mt-1">Root Mandates</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-3xl font-bold">{delegations.length}</div>
              <p className="text-sm text-muted-foreground mt-1">Delegations</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-3xl font-bold">
                {mandateList.length > 0
                  ? Math.max(...mandateList.map((m) => (m as Record<string, unknown>).delegation_depth as number ?? 0))
                  : 0}
              </div>
              <p className="text-sm text-muted-foreground mt-1">Max Depth</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Delegation Tree</CardTitle>
        </CardHeader>
        <CardContent>
          {mandateList.length === 0 ? (
            <div className="py-8 text-center text-muted-foreground">
              <p>No mandates to display.</p>
              <p className="text-sm mt-1">Create mandates and delegations to see the PoA map.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {rootMandates.map((mandate) => (
                <MandateTreeNode
                  key={mandate.mandate_id}
                  mandate={mandate}
                  allMandates={mandateList}
                  depth={0}
                />
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">About PoA Maps</CardTitle>
        </CardHeader>
        <CardContent className="prose prose-sm max-w-none text-muted-foreground">
          <p>
            The Power of Attorney Map visualizes how mandates delegate authority through a hierarchy.
            Each root mandate can create child delegations with narrowed scope, constrained budgets,
            and reduced maximum depths — following the PP-07 delegation narrowing rules.
          </p>
          <p>
            The <code>generatePoaMap()</code> function in the Management API produces a flat list
            of all mandates with their delegation depth, parent references, and current status.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}

function MandateTreeNode({
  mandate,
  allMandates,
  depth,
}: {
  mandate: { mandate_id: string; status: string; subject_agent_id: string; governance_profile: string };
  allMandates: Array<Record<string, unknown>>;
  depth: number;
}) {
  const children = allMandates.filter(
    (m) => m.parent_mandate_id === mandate.mandate_id
  );

  return (
    <div style={{ marginLeft: depth * 24 }}>
      <div className="flex items-center gap-3 p-3 bg-muted/30 rounded-lg border border-border/50">
        {depth > 0 && (
          <span className="text-muted-foreground text-xs">↳</span>
        )}
        <span className="font-mono text-xs font-medium">{mandate.mandate_id}</span>
        <Badge
          variant="secondary"
          className={
            mandate.status === "ACTIVE" ? "bg-green-100 text-green-800"
            : mandate.status === "DRAFT" ? "bg-amber-100 text-amber-800"
            : ""
          }
        >
          {mandate.status}
        </Badge>
        <span className="text-xs text-muted-foreground">
          {mandate.subject_agent_id}
        </span>
      </div>
      {children.map((child) => (
        <MandateTreeNode
          key={child.mandate_id as string}
          mandate={child as typeof mandate}
          allMandates={allMandates}
          depth={depth + 1}
        />
      ))}
    </div>
  );
}
