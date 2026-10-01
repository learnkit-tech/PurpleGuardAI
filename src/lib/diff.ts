/**
 * Minimal line-based diff (LCS) used by the Developer Panel.
 * Produces unified-style hunks around changed regions.
 */

export type DiffLineType = "context" | "added" | "removed";

export interface DiffLine {
  type: DiffLineType;
  text: string;
  /** 1-indexed line number in the old file. Absent for added lines. */
  oldNumber?: number;
  /** 1-indexed line number in the new file. Absent for removed lines. */
  newNumber?: number;
}

export interface DiffHunk {
  header: string;
  lines: DiffLine[];
}

/** Classic LCS table diff over lines. Fine for the small files we display. */
function lcsTable(a: string[], b: string[]): number[][] {
  const table: number[][] = Array.from({ length: a.length + 1 }, () =>
    new Array<number>(b.length + 1).fill(0),
  );
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      table[i][j] =
        a[i] === b[j]
          ? table[i + 1][j + 1] + 1
          : Math.max(table[i + 1][j], table[i][j + 1]);
    }
  }
  return table;
}

function walkTable(
  table: number[][],
  a: string[],
  b: string[],
): Array<{ type: DiffLineType; text: string }> {
  const result: Array<{ type: DiffLineType; text: string }> = [];
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      result.push({ type: "context", text: a[i] });
      i++;
      j++;
    } else if (table[i + 1][j] >= table[i][j + 1]) {
      result.push({ type: "removed", text: a[i] });
      i++;
    } else {
      result.push({ type: "added", text: b[j] });
      j++;
    }
  }
  while (i < a.length) {
    result.push({ type: "removed", text: a[i] });
    i++;
  }
  while (j < b.length) {
    result.push({ type: "added", text: b[j] });
    j++;
  }
  return result;
}

const CONTEXT_RADIUS = 3;
/** Context lines between two changes closer than this merge into one hunk. */
const HUNK_GAP = 6;

function findLastIndex<T>(arr: T[], pred: (item: T) => boolean): number {
  for (let i = arr.length - 1; i >= 0; i--) {
    if (pred(arr[i])) return i;
  }
  return -1;
}

/** Compute unified-style hunks between two versions of a file. */
export function diffLines(oldText: string, newText: string): DiffHunk[] {
  if (oldText === newText) return [];

  const a = oldText.split("\n");
  const b = newText.split("\n");
  const table = lcsTable(a, b);
  const ops = walkTable(table, a, b);

  // Assign old/new line numbers.
  let oldNo = 1;
  let newNo = 1;
  const numbered: DiffLine[] = ops.map((op) => {
    const line: DiffLine = { type: op.type, text: op.text };
    if (op.type === "context") {
      line.oldNumber = oldNo++;
      line.newNumber = newNo++;
    } else if (op.type === "removed") {
      line.oldNumber = oldNo++;
    } else {
      line.newNumber = newNo++;
    }
    return line;
  });

  // Group changed regions into hunks with bounded surrounding context.
  const hunks: DiffHunk[] = [];
  let current: DiffLine[] | null = null;
  let gap = 0;

  for (const line of numbered) {
    if (line.type !== "context") {
      if (!current) current = [];
      current.push(line);
      gap = 0;
    } else if (current) {
      gap += 1;
      if (gap <= HUNK_GAP) {
        current.push(line);
      } else {
        hunks.push({ header: "", lines: current });
        current = null;
        gap = 0;
      }
    }
  }
  if (current) hunks.push({ header: "", lines: current });

  for (const hunk of hunks) {
    const firstChange = hunk.lines.findIndex((l) => l.type !== "context");
    if (firstChange > CONTEXT_RADIUS) {
      hunk.lines = hunk.lines.slice(firstChange - CONTEXT_RADIUS);
    }
    const lastChange = findLastIndex(hunk.lines, (l) => l.type !== "context");
    if (lastChange >= 0 && hunk.lines.length - 1 - lastChange > CONTEXT_RADIUS) {
      hunk.lines = hunk.lines.slice(0, lastChange + 1 + CONTEXT_RADIUS);
    }
    const first = hunk.lines[0];
    const startOld = first.oldNumber ?? first.newNumber ?? 1;
    const startNew = first.newNumber ?? first.oldNumber ?? 1;
    hunk.header = `@@ -${startOld} +${startNew} @@`;
  }

  return hunks;
}
