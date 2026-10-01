import { createContext, useContext, useMemo, useState, type ReactNode } from "react";

/**
 * Shared, app-wide project selection. Panels read `projectId` (null = all
 * projects) and route through the shared PanelShell selector, so every
 * surface operates on the same target.
 */
interface ProjectSelectionValue {
  projectId: string | null;
  setProjectId: (id: string | null) => void;
}

const ProjectSelectionContext = createContext<ProjectSelectionValue>({
  projectId: null,
  setProjectId: () => {},
});

export function ProjectSelectionProvider({ children }: { children: ReactNode }) {
  const [projectId, setProjectId] = useState<string | null>(null);
  const value = useMemo(
    () => ({ projectId, setProjectId }),
    [projectId],
  );
  return (
    <ProjectSelectionContext.Provider value={value}>
      {children}
    </ProjectSelectionContext.Provider>
  );
}

export function useProjectSelection() {
  return useContext(ProjectSelectionContext);
}
