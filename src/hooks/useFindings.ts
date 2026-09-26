import { useMutation, useQuery } from "convex/react";
import { useCallback, useMemo } from "react";
import { api } from "@/convex/_generated/api";
import { ingestFindings, type EngineFinding } from "@/components/developer/ingest";
import { REAL_FINDINGS } from "@/components/developer/seed";

export type FindingsSource = "convex" | "seed";

export interface ImportOutcome {
  ok: boolean;
  count: number;
  errors: string[];
}

/**
 * Findings for the Developer Panel.
 *
 * Backed by the Convex `findings` table (orchestrator.py output imported as
 * JSON). While the table is empty the panel falls back to the real seed
 * findings so the loop stays demonstrable; importing JSON switches the panel
 * to engine data permanently until cleared.
 */
export function useFindings() {
  const rows = useQuery(api.findings.list);
  const replaceAll = useMutation(api.findings.replaceAll);

  const fromConvex = useMemo<EngineFinding[] | null>(() => {
    if (!rows || rows.length === 0) return null;
    const result = ingestFindings(rows.map((r) => r.payload));
    return result.findings.length > 0 ? result.findings : null;
  }, [rows]);

  const findings = fromConvex ?? REAL_FINDINGS;
  const source: FindingsSource = fromConvex ? "convex" : "seed";

  const finding = useCallback(
    (id: string | undefined) =>
      id ? findings.find((f) => f.id === id) : undefined,
    [findings],
  );

  const importJson = useCallback(
    async (text: string): Promise<ImportOutcome> => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        return { ok: false, count: 0, errors: ["Invalid JSON — nothing imported."] };
      }
      const result = ingestFindings(parsed);
      if (result.findings.length === 0) {
        return {
          ok: false,
          count: 0,
          errors: result.errors.length > 0 ? result.errors : ["No valid findings found."],
        };
      }
      await replaceAll({ payloads: result.findings });
      return { ok: true, count: result.findings.length, errors: result.errors };
    },
    [replaceAll],
  );

  const clearAll = useCallback(async () => {
    await replaceAll({ payloads: [] });
  }, [replaceAll]);

  return { findings, source, loading: rows === undefined, finding, importJson, clearAll };
}
