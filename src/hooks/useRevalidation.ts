import { useMutation, useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import type { FunctionReturnType } from "convex/server";

export type RevalidationRecord = FunctionReturnType<
  typeof api.revalidations.latest
>;

/**
 * Re-run validation state for one finding: the queued revalidation request
 * and its engine-returned verdict (if the engine has resolved one yet).
 */
export function useRevalidation(findingId: string) {
  const requestRevalidation = useMutation(api.revalidations.requestRevalidation);
  const latest = useQuery(api.revalidations.latest, { findingId });

  const queue = async (): Promise<string> => {
    const res = await requestRevalidation({ findingId });
    return res.revalidationId;
  };

  return { queue, latest };
}
