const LEGACY_TOKEN_KEY = "artex_token";

export interface CurrentUser {
  id: string;
  name: string;
  username: string;
  email: string;
  avatar: string;
  role: string;
}

export const auth = {
  getCurrentUser(): CurrentUser {
    return { id: "1", name: "ARTEX", username: "ARTEX", email: "", avatar: "", role: "operator" };
  },
};

// Older consoles wrote a JWT to localStorage. Remove that copy before any
// session check; a valid token can be exchanged once for a server-owned cookie.
let migration: Promise<void> | null = null;

export function migrateLegacySession(): Promise<void> {
  if (migration) return migration;
  migration = (async () => {
    if (typeof window === "undefined") return;
    const token = localStorage.getItem(LEGACY_TOKEN_KEY);
    localStorage.removeItem(LEGACY_TOKEN_KEY);
    if (!token || process.env.NEXT_PUBLIC_MOCK === "1") return;
    await fetch("/api/auth/migrate", {
      method: "POST",
      credentials: "same-origin",
      headers: { Authorization: `Bearer ${token}`, "X-ARTEX-Browser-Session": "1" },
    });
  })();
  return migration;
}
