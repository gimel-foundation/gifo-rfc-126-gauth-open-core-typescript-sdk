import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useGovernanceProfiles } from "@workspace/api-client-react";

const DEFAULT_PROFILES = [
  {
    profile_name: "strict",
    description: "Maximum oversight. All actions require explicit approval. Suitable for high-risk autonomous agents.",
    phase: "exploration" as const,
    tariff_code: "L",
    checks: "All 16 PEP checks enforced, budget hard limits, no delegation",
  },
  {
    profile_name: "standard",
    description: "Balanced governance. Common actions pre-approved, unusual actions flagged. Default profile.",
    phase: "supervised" as const,
    tariff_code: "M",
    checks: "14/16 PEP checks, budget soft limits, single-level delegation",
  },
  {
    profile_name: "permissive",
    description: "Minimal friction. Broad action approval with audit logging. For trusted, well-tested agents.",
    phase: "autonomous" as const,
    tariff_code: "O",
    checks: "Core safety checks only, budget monitoring, multi-level delegation",
  },
];

const PHASE_COLORS: Record<string, string> = {
  exploration: "bg-blue-100 text-blue-800",
  supervised: "bg-amber-100 text-amber-800",
  autonomous: "bg-green-100 text-green-800",
};

export default function ProfilesPage() {
  const { data } = useGovernanceProfiles();
  const serverProfiles = data?.profiles ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Governance Profiles</h1>
        <p className="text-muted-foreground mt-1">
          Pre-defined governance profiles that control agent behavior and enforcement levels.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {DEFAULT_PROFILES.map((profile) => (
          <Card key={profile.profile_name} className="flex flex-col">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-lg capitalize">{profile.profile_name}</CardTitle>
                <Badge className={PHASE_COLORS[profile.phase]}>
                  {profile.phase}
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="flex-1 space-y-4">
              <p className="text-sm text-muted-foreground">{profile.description}</p>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-muted-foreground">Tariff Code</span>
                  <Badge variant="secondary" className="text-xs font-mono">{profile.tariff_code}</Badge>
                </div>
                <div className="text-xs text-muted-foreground bg-muted/50 p-3 rounded-lg">
                  {profile.checks}
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Tariff Model</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b">
                  <th className="text-left py-3 px-4 font-medium text-muted-foreground">Code</th>
                  <th className="text-left py-3 px-4 font-medium text-muted-foreground">Level</th>
                  <th className="text-left py-3 px-4 font-medium text-muted-foreground">Type</th>
                  <th className="text-left py-3 px-4 font-medium text-muted-foreground">Description</th>
                </tr>
              </thead>
              <tbody>
                {[
                  { code: "O", level: "Open", type: "Base", desc: "Community / open-source adapters" },
                  { code: "M", level: "Managed", type: "Base", desc: "Enterprise adapters with SLA" },
                  { code: "L", level: "Licensed", type: "Base", desc: "Licensed connectors with support" },
                  { code: "M+O", level: "Managed", type: "Hybrid", desc: "Managed primary + open fallback" },
                  { code: "L+O", level: "Licensed", type: "Hybrid", desc: "Licensed primary + open fallback" },
                ].map((row) => (
                  <tr key={row.code} className="border-b last:border-0">
                    <td className="py-3 px-4 font-mono font-medium">{row.code}</td>
                    <td className="py-3 px-4">{row.level}</td>
                    <td className="py-3 px-4">
                      <Badge variant="secondary" className="text-xs">{row.type}</Badge>
                    </td>
                    <td className="py-3 px-4 text-muted-foreground">{row.desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
