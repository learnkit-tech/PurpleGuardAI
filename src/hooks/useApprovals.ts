import { useMutation, useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import { useState } from "react";
import type { FunctionReturnType } from "convex/server";

export type ApprovalRecord = FunctionReturnType<typeof api.approvals.latest>;

export function useApprovals(findingId: string) {
  const requestApproval = useMutation(api.approvals.requestApproval);
  const latest = useQuery(api.approvals.latest, { findingId });
  const pendingAll = useQuery(api.approvals.pending);

  const [submitting, setSubmitting] = useState(false);

  const pendingForFinding =
    (pendingAll ?? []).some((d) => d.findingId === findingId) ||
    latest?.status === "pending";

  const submit = async (source: string, buffer: string): Promise<string> => {
    setSubmitting(true);
    try {
      const res = await requestApproval({ findingId, source, buffer });
      return res.approvalId;
    } finally {
      setSubmitting(false);
    }
  };

  return { submit, pendingForFinding, latest, submitting };
}
