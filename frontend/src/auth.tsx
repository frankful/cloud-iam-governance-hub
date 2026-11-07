import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import {
  ApiError,
  api,
  clearAuthUser,
  clearToken,
  getDevUser,
  getToken,
  setAuthMode,
  setAuthUser,
  setDevUser,
} from "./api/client";
import type { AuthMode, AuthUser } from "./api/types";
import i18n from "./i18n";

interface AuthContextValue {
  mode: AuthMode | null;
  user: AuthUser | null;
  loading: boolean;
  error: string | null;
  login: (token: string) => Promise<AuthUser>;
  loginDev: (userID: string) => Promise<AuthUser>;
  logout: () => void;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function hasRole(user: AuthUser | null, ...roles: string[]): boolean {
  if (!user) return false;
  return user.roles.some((role) => roles.includes(role));
}

export function landingPath(user: AuthUser | null): string {
  return hasRole(user, "platform_admin", "approval_admin") ? "/" : "/tickets";
}

function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return error.message;
  return i18n.t("login.failed");
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [mode, setMode] = useState<AuthMode | null>(null);
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const applyUser = useCallback((next: AuthUser | null) => {
    setUser(next);
    if (next) setAuthUser(next);
    else clearAuthUser();
  }, []);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const config = await api.getAuthConfig();
      setAuthMode(config.mode);
      setMode(config.mode);
      if (config.mode === "development") {
        const devUser = getDevUser() || "admin";
        setDevUser(devUser);
        const identity = await api.getMe();
        applyUser(identity);
      } else if (getToken()) {
        const identity = await api.getMe();
        applyUser(identity);
      } else {
        applyUser(null);
      }
    } catch (err) {
      if (!(err instanceof ApiError && err.status === 401)) {
        setError(errorMessage(err));
      }
      clearToken();
      applyUser(null);
    } finally {
      setLoading(false);
    }
  }, [applyUser]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    const expire = () => applyUser(null);
    window.addEventListener("auth-expired", expire);
    return () => window.removeEventListener("auth-expired", expire);
  }, [applyUser]);

  const login = useCallback(
    async (token: string) => {
      setError(null);
      const identity = await api.loginWithToken(token);
      applyUser(identity);
      return identity;
    },
    [applyUser],
  );

  const loginDev = useCallback(
    async (userID: string) => {
      const normalized = userID.trim();
      if (!normalized) throw new Error("development user ID must not be empty");
      setDevUser(normalized);
      setError(null);
      const identity = await api.getMe();
      applyUser(identity);
      return identity;
    },
    [applyUser],
  );

  const logout = useCallback(() => {
    api.logout();
    applyUser(null);
  }, [applyUser]);

  const value = useMemo<AuthContextValue>(
    () => ({ mode, user, loading, error, login, loginDev, logout, refresh }),
    [mode, user, loading, error, login, loginDev, logout, refresh],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthProvider");
  return value;
}
