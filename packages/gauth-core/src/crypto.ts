const textEncoder = new TextEncoder();

export function canonicalJson(obj: unknown): string {
  return JSON.stringify(sortKeys(obj));
}

function sortKeys(value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map(sortKeys);
  if (typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortKeys((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

export async function sha256Hex(data: string): Promise<string> {
  const hashBuffer = await crypto.subtle.digest("SHA-256", textEncoder.encode(data));
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function computeScopeChecksum(scope: {
  governance_profile: string;
  phase: string;
  allowed_paths?: string[];
  denied_paths?: string[];
  active_modules?: string[];
  tool_permissions_hash: string;
  platform_permissions_hash: string;
}): Promise<string> {
  const input = canonicalJson({
    governance_profile: scope.governance_profile,
    phase: scope.phase,
    allowed_paths: scope.allowed_paths ?? [],
    denied_paths: scope.denied_paths ?? [],
    active_modules: scope.active_modules ?? [],
    tool_permissions_hash: scope.tool_permissions_hash,
    platform_permissions_hash: scope.platform_permissions_hash,
  });
  const hash = await sha256Hex(input);
  return `sha256:${hash}`;
}

export async function computeToolPermissionsHash(
  coreVerbs: Record<string, unknown>,
): Promise<string> {
  const hash = await sha256Hex(canonicalJson(coreVerbs));
  return `sha256:${hash}`;
}

export async function computePlatformPermissionsHash(
  platformPermissions: Record<string, unknown> | undefined,
): Promise<string> {
  const hash = await sha256Hex(canonicalJson(platformPermissions ?? {}));
  return `sha256:${hash}`;
}

export function matchGlob(pattern: string, path: string): boolean {
  const regexStr = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "<<GLOBSTAR>>")
    .replace(/\*/g, "[^/]*")
    .replace(/<<GLOBSTAR>>/g, ".*")
    .replace(/\?/g, "[^/]");

  if (pattern.endsWith("/")) {
    return new RegExp(`^${regexStr}`).test(path);
  }

  return new RegExp(`^${regexStr}$`).test(path) || path.startsWith(pattern);
}
