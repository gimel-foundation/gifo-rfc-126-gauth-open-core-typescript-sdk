import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import type {
  QueryFunction,
  QueryKey,
  UseQueryOptions,
  UseQueryResult,
  UseMutationOptions,
  UseMutationResult,
} from "@tanstack/react-query";

import type {
  HealthStatus,
  MandateSummary,
  MandateDetail,
  PoaMapEntry,
  AuditLogEntry,
  CredentialSummary,
  GovernanceProfileSummary,
} from "./api.schemas";

import { customFetch } from "../custom-fetch";
import type { ErrorType } from "../custom-fetch";

type SecondParameter<T extends (...args: never) => unknown> = Parameters<T>[1];

export const getHealthCheckUrl = () => `/api/healthz`;

export const healthCheck = async (
  options?: RequestInit,
): Promise<HealthStatus> => {
  return customFetch<HealthStatus>(getHealthCheckUrl(), {
    ...options,
    method: "GET",
  });
};

export const getHealthCheckQueryKey = () => [`/api/healthz`] as const;

export function useHealthCheck<
  TData = HealthStatus,
  TError = ErrorType<unknown>,
>(options?: {
  query?: UseQueryOptions<HealthStatus, TError, TData>;
  request?: SecondParameter<typeof customFetch>;
}): UseQueryResult<TData, TError> {
  const { query: queryOptions, request: requestOptions } = options ?? {};
  return useQuery({
    queryKey: getHealthCheckQueryKey(),
    queryFn: ({ signal }) => healthCheck({ signal, ...requestOptions }),
    ...queryOptions,
  });
}

export const getMandatesUrl = () => `/api/gauth/mgmt/v1/mandates`;

export const fetchMandates = async (
  options?: RequestInit,
): Promise<MandateSummary[]> => {
  return customFetch<MandateSummary[]>(getMandatesUrl(), {
    ...options,
    method: "GET",
  });
};

export const getMandatesQueryKey = () => [`/api/gauth/mgmt/v1/mandates`] as const;

export function useMandates<
  TData = MandateSummary[],
  TError = ErrorType<unknown>,
>(options?: {
  query?: UseQueryOptions<MandateSummary[], TError, TData>;
}): UseQueryResult<TData, TError> {
  const { query: queryOptions } = options ?? {};
  return useQuery({
    queryKey: getMandatesQueryKey(),
    queryFn: ({ signal }) => fetchMandates({ signal }),
    ...queryOptions,
  });
}

export const getMandateUrl = (id: string) => `/api/gauth/mgmt/v1/mandates/${id}`;

export const fetchMandate = async (
  id: string,
  options?: RequestInit,
): Promise<MandateDetail> => {
  return customFetch<MandateDetail>(getMandateUrl(id), {
    ...options,
    method: "GET",
  });
};

export const getMandateQueryKey = (id: string) => [`/api/gauth/mgmt/v1/mandates`, id] as const;

export function useMandate<
  TData = MandateDetail,
  TError = ErrorType<unknown>,
>(id: string, options?: {
  query?: UseQueryOptions<MandateDetail, TError, TData>;
}): UseQueryResult<TData, TError> {
  const { query: queryOptions } = options ?? {};
  return useQuery({
    queryKey: getMandateQueryKey(id),
    queryFn: ({ signal }) => fetchMandate(id, { signal }),
    enabled: !!id,
    ...queryOptions,
  });
}

export const createMandate = async (
  body: Record<string, unknown>,
  options?: RequestInit,
): Promise<MandateDetail> => {
  return customFetch<MandateDetail>(getMandatesUrl(), {
    ...options,
    method: "POST",
    body: JSON.stringify(body),
    headers: { "Content-Type": "application/json" },
  });
};

export function useCreateMandate<TError = ErrorType<unknown>>(
  options?: UseMutationOptions<MandateDetail, TError, Record<string, unknown>>,
): UseMutationResult<MandateDetail, TError, Record<string, unknown>> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body) => createMandate(body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: getMandatesQueryKey() });
    },
    ...options,
  });
}

export const getPoaMapUrl = () => `/api/gauth/mgmt/v1/poa-map`;

export const fetchPoaMap = async (
  options?: RequestInit,
): Promise<PoaMapEntry[]> => {
  return customFetch<PoaMapEntry[]>(getPoaMapUrl(), {
    ...options,
    method: "GET",
  });
};

export const getPoaMapQueryKey = () => [`/api/gauth/mgmt/v1/poa-map`] as const;

export function usePoaMap<
  TData = PoaMapEntry[],
  TError = ErrorType<unknown>,
>(options?: {
  query?: UseQueryOptions<PoaMapEntry[], TError, TData>;
}): UseQueryResult<TData, TError> {
  const { query: queryOptions } = options ?? {};
  return useQuery({
    queryKey: getPoaMapQueryKey(),
    queryFn: ({ signal }) => fetchPoaMap({ signal }),
    ...queryOptions,
  });
}

export const getAuditLogUrl = () => `/api/gauth/mgmt/v1/audit-log`;

export const fetchAuditLog = async (
  options?: RequestInit,
): Promise<{ entries: AuditLogEntry[]; total: number }> => {
  return customFetch<{ entries: AuditLogEntry[]; total: number }>(getAuditLogUrl(), {
    ...options,
    method: "GET",
  });
};

export const getAuditLogQueryKey = () => [`/api/gauth/mgmt/v1/audit-log`] as const;

export function useAuditLog<
  TData = { entries: AuditLogEntry[]; total: number },
  TError = ErrorType<unknown>,
>(options?: {
  query?: UseQueryOptions<{ entries: AuditLogEntry[]; total: number }, TError, TData>;
}): UseQueryResult<TData, TError> {
  const { query: queryOptions } = options ?? {};
  return useQuery({
    queryKey: getAuditLogQueryKey(),
    queryFn: ({ signal }) => fetchAuditLog({ signal }),
    ...queryOptions,
  });
}

export const getCredentialsUrl = () => `/api/gauth/mgmt/v1/credentials`;

export const fetchCredentials = async (
  options?: RequestInit,
): Promise<{ credentials: CredentialSummary[] }> => {
  return customFetch<{ credentials: CredentialSummary[] }>(getCredentialsUrl(), {
    ...options,
    method: "GET",
  });
};

export const getCredentialsQueryKey = () => [`/api/gauth/mgmt/v1/credentials`] as const;

export function useCredentials<
  TData = { credentials: CredentialSummary[] },
  TError = ErrorType<unknown>,
>(options?: {
  query?: UseQueryOptions<{ credentials: CredentialSummary[] }, TError, TData>;
}): UseQueryResult<TData, TError> {
  const { query: queryOptions } = options ?? {};
  return useQuery({
    queryKey: getCredentialsQueryKey(),
    queryFn: ({ signal }) => fetchCredentials({ signal }),
    ...queryOptions,
  });
}

export const getGovernanceProfilesUrl = () => `/api/gauth/mgmt/v1/governance-profiles`;

export const fetchGovernanceProfiles = async (
  options?: RequestInit,
): Promise<{ profiles: GovernanceProfileSummary[] }> => {
  return customFetch<{ profiles: GovernanceProfileSummary[] }>(getGovernanceProfilesUrl(), {
    ...options,
    method: "GET",
  });
};

export const getGovernanceProfilesQueryKey = () => [`/api/gauth/mgmt/v1/governance-profiles`] as const;

export function useGovernanceProfiles<
  TData = { profiles: GovernanceProfileSummary[] },
  TError = ErrorType<unknown>,
>(options?: {
  query?: UseQueryOptions<{ profiles: GovernanceProfileSummary[] }, TError, TData>;
}): UseQueryResult<TData, TError> {
  const { query: queryOptions } = options ?? {};
  return useQuery({
    queryKey: getGovernanceProfilesQueryKey(),
    queryFn: ({ signal }) => fetchGovernanceProfiles({ signal }),
    ...queryOptions,
  });
}

export const getPepHealthUrl = () => `/api/gauth/pep/v1/health`;

export const fetchPepHealth = async (
  options?: RequestInit,
): Promise<HealthStatus> => {
  return customFetch<HealthStatus>(getPepHealthUrl(), {
    ...options,
    method: "GET",
  });
};

export function usePepHealth<
  TData = HealthStatus,
  TError = ErrorType<unknown>,
>(options?: {
  query?: UseQueryOptions<HealthStatus, TError, TData>;
}): UseQueryResult<TData, TError> {
  const { query: queryOptions } = options ?? {};
  return useQuery({
    queryKey: [`/api/gauth/pep/v1/health`],
    queryFn: ({ signal }) => fetchPepHealth({ signal }),
    ...queryOptions,
  });
}
