import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { AuthConfig, AuthConfigMethods, AuthPayload, User } from "./auth";

interface AuthProviderProps {
  children: React.ReactNode;
  authConfig: AuthConfig;
}

type Nullable<T extends object> = {
  [K in keyof T]: T[K] extends (...data: any[]) => infer R ? (...data: Parameters<T[K]>) => R | null : T[K];
};

const AuthContext = createContext<Nullable<AuthConfigMethods>>({
  applyAxiosMiddleware: () => null,
  checkAccessTokenIsExpired: () => null,
  getUser: () => null,
  setUser: () => null,
  signIn: () => null,
  signOut: () => null,
});

const DataContext = createContext<{ payload: AuthPayload | null }>({ payload: null });

type C = {
  user: User;
  payload: AuthPayload;
};

const AuthProvider = ({ children, authConfig }: AuthProviderProps) => {
  const [payload, setPayload] = useState<AuthPayload | null>(null);

  useEffect(() => {
    const unsubscribe = authConfig.subscribe<C>("SIGNIN", ({ payload }) => setPayload(payload));

    return unsubscribe;
  }, [authConfig]);

  const value = useMemo(() => {
    return { payload };
  }, [payload]);

  return (
    <AuthContext.Provider value={authConfig}>
      <DataContext.Provider value={value}>{children}</DataContext.Provider>
    </AuthContext.Provider>
  );
};

const useAuthCredential = () => useContext(DataContext);
const useAuthConfig = () => useContext(AuthContext);

export { AuthProvider, useAuthConfig, useAuthCredential };
