import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useCredentials } from "@workspace/api-client-react";

export default function CredentialsPage() {
  const { data, isLoading, error } = useCredentials();

  const credentials = data?.credentials ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Credentials</h1>
        <p className="text-muted-foreground mt-1">
          W3C Verifiable Credentials issued from PoA mandates.
        </p>
      </div>

      {isLoading && (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            Loading credentials...
          </CardContent>
        </Card>
      )}

      {error && (
        <Card>
          <CardContent className="py-12 text-center text-red-600">
            Failed to load credentials.
          </CardContent>
        </Card>
      )}

      {!isLoading && !error && credentials.length === 0 && (
        <Card>
          <CardContent className="py-12 text-center">
            <div className="space-y-2">
              <p className="text-muted-foreground">No credentials issued yet.</p>
              <p className="text-sm text-muted-foreground">
                Issue credentials via the VCI/VP API endpoints (POST /api/gauth/vci/v1/credentials/issue).
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {credentials.length > 0 && (
        <div className="space-y-3">
          {credentials.map((cred) => (
            <Card key={cred.credential_id}>
              <CardContent className="py-4">
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-sm">{cred.credential_id}</span>
                      <Badge variant={cred.status === "VALID" ? "default" : "destructive"}>
                        {cred.status}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-4 text-sm text-muted-foreground">
                      <span>Type: {cred.type}</span>
                      <span>Mandate: {cred.mandate_id}</span>
                      {cred.issuer_did && <span>Issuer: {cred.issuer_did}</span>}
                    </div>
                  </div>
                  <span className="text-sm text-muted-foreground">
                    {new Date(cred.issued_at).toLocaleDateString()}
                  </span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Supported Standards</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {[
              { name: "W3C Verifiable Credentials", version: "v2.0" },
              { name: "Data Integrity Proofs", version: "ecdsa-rdfc-2019" },
              { name: "DID Resolution", version: "did:key / did:web" },
              { name: "Bitstring Status List", version: "v1.0" },
              { name: "OpenID4VCI", version: "Draft 14" },
              { name: "OpenID4VP", version: "Draft 20" },
            ].map((std) => (
              <div key={std.name} className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
                <span className="text-sm font-medium">{std.name}</span>
                <Badge variant="secondary" className="text-xs">{std.version}</Badge>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
