import { createContext, useContext, type ReactNode } from "react";
import type { Permission, SessionInfo } from "./api";

interface SessionValue {
  session: SessionInfo;
  can: (p: Permission) => boolean;
  reloadSession: () => Promise<void>;
  pendingApprovals: number;
  setPendingApprovals: (n: number) => void;
}

const SessionContext = createContext<SessionValue | null>(null);

export function SessionProvider({ value, children }: { value: SessionValue; children: ReactNode }) {
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionValue {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error("SessionProvider missing");
  return ctx;
}
