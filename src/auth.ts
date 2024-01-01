import { AxiosError, AxiosInstance } from "axios";
import * as jose from "jose";
import createAuthRefreshInterceptor from "axios-auth-refresh";
import EventEmitter from "eventemitter2";

type TypeDefaultAsNull<T> = T | null;

type AuthStorageOptions = {
  key?: string;
  storage?: Storage;
};

export type AuthPayload = {
  readonly accessToken: string;
  readonly refreshToken: string;
  expiresIn?: number;
};

type AuthConfigOptions = {
  authorize: <T extends User>(user: T) => Promise<AuthPayload>;
  signOutCallback?: () => Promise<void>;
  storageOptions?: AuthStorageOptions;
  scope?: string;
};

export type User = {
  [key: string]: any;
  sub: string;
};

type ExtendUser<T extends Record<string, any>> = Omit<T, "sub"> & User;

export interface AuthConfigMethods {
  signIn<T extends User>(user: T): Promise<void>;
  setUser(payload: AuthPayload): Promise<void>;
  getUser<T extends Record<string, any>>(): Promise<TypeDefaultAsNull<ExtendUser<T>>>;
  signOut(): Promise<void>;
  checkAccessTokenIsExpired(handleRefreshToken: (refreshToken: string) => Promise<AuthPayload>): Promise<void>;
  applyAxiosMiddleware(instance: AxiosInstance): void;
}

type AuthEvent = "SIGNIN" | "SIGNOUT" | "SETUSER";

class AuthConfig implements AuthConfigMethods {
  private readonly emitter: EventEmitter;

  private authorize: AuthConfigOptions["authorize"];
  private signOutCallback: AuthConfigOptions["signOutCallback"];
  private storageOptions: Required<AuthStorageOptions> = { key: "token", storage: localStorage };
  private user: TypeDefaultAsNull<User> = null;
  private authPayload: TypeDefaultAsNull<AuthPayload> = null;
  private axiosInstance: TypeDefaultAsNull<AxiosInstance> = null;
  private axiosInterceptorEjectIds: number[] = [];

  private subscribers: Map<AuthEvent, () => void> = new Map();

  constructor({ authorize, signOutCallback, scope, storageOptions }: AuthConfigOptions) {
    this.emitter = new EventEmitter();

    this.authorize = authorize;
    this.signOutCallback = signOutCallback;

    if (storageOptions) this.setStorageOptions(storageOptions, scope);
  }

  public subscribe = <T>(event: AuthEvent, callback: (...data: T[]) => void) => {
    this.emitter.on(event, callback);

    const unsubscribe = () => {
      this.emitter.off(event, callback);
      this.subscribers.delete(event);
    };

    this.subscribers.set(event, unsubscribe);

    return unsubscribe;
  };

  public unsubscribe = (event: AuthEvent) => {
    this.subscribers.get(event)?.();
  };

  public signIn = async <T extends User>(user: T, onSuccess?: (payload: AuthPayload) => void) => {
    try {
      const payload = await this.authorize(user);

      if (!payload) {
        console.error("The authorize callback returns some invalid data");

        return;
      }

      this.user = user;

      await this.setUser(payload);

      this.emitter.emit("SIGNIN", { payload, user });

      console.log("The user has beed successfully signed in");

      if (onSuccess) onSuccess(payload);
    } catch (error) {
      console.error(error);

      this.user = null;

      this.storageOptions.storage.removeItem(this.storageOptions.key);
    }
  };

  public setUser = (payload: AuthPayload) => {
    return new Promise<void>((resolve, reject) => {
      try {
        this.authPayload = payload;

        this.persistJWTTokenPayload(payload);

        this.emitter.emit("SETUSER", payload);

        console.log("The user payload has been successfully updated.");

        resolve();
      } catch (error) {
        console.error(error);

        reject(error);
      }
    });
  };

  public getUser = <T extends Record<string, any>>() => {
    return new Promise<TypeDefaultAsNull<ExtendUser<T>>>((resolve, reject) => {
      try {
        const payload = this.storageOptions.storage.getItem(this.storageOptions.key);

        if (payload === null) return resolve(null);

        return resolve(this.user as ExtendUser<T>);
      } catch (error) {
        console.error(error);

        reject(error);

        return resolve(null);
      }
    });
  };

  public checkAccessTokenIsExpired = async (handleRefreshToken: (refreshToken: string) => Promise<AuthPayload>) => {
    if (!this.authPayload || !this.authPayload.accessToken) return;

    const payload = jose.decodeJwt(this.authPayload.accessToken);

    if (payload === null) return;

    this.tryOverrideTokenExpiration(this.authPayload, payload);

    if (this.authPayload.expiresIn && Date.now() > this.authPayload.expiresIn) {
      try {
        const newPayload = await handleRefreshToken(this.authPayload.refreshToken);

        await this.setUser(newPayload);
      } catch (error) {
        console.error(error);

        this.ejectTriggeredInterceptors();
        this.storageOptions.storage.removeItem(this.storageOptions.key);
        this.user = null;
      }
    }
  };

  public signOut = async () => {
    this.storageOptions.storage.removeItem(this.storageOptions.key);

    this.user = null;

    this.ejectTriggeredInterceptors();

    this.emitter.emit("SIGNOUT");

    if (this.signOutCallback) await this.signOutCallback();
  };

  public applyAxiosMiddleware = (instance: AxiosInstance) => {
    this.axiosInstance = instance;

    this.axiosInterceptorEjectIds.push(
      createAuthRefreshInterceptor(instance, (failedRequest: AxiosError<any>) => {
        if (!failedRequest.response) {
          return Promise.reject(failedRequest);
        }
        try {
          if (this.authPayload) {
            const accessToken = this.authPayload.accessToken;

            if (accessToken) {
              failedRequest.response.headers.authorization = `Bearer ${accessToken}`;

              return Promise.resolve(failedRequest);
            }
          }

          return Promise.reject(failedRequest);
        } catch (error) {
          console.error(error);

          return Promise.reject(failedRequest);
        }
      })
    );

    this.axiosInterceptorEjectIds.push(
      instance.interceptors.request.use((config) => {
        if (this.authPayload) {
          const accessToken = this.authPayload.accessToken;

          if (accessToken) {
            config.headers.authorization = `Bearer ${accessToken}`;
          }
        }

        return config;
      }, console.error)
    );
  };

  private setStorageOptions = (storageOptions: AuthStorageOptions, scope?: string) => {
    const key = storageOptions.key || this.storageOptions.key;

    this.storageOptions.key = scope ? scope + ":" + key : key;

    this.storageOptions.storage = storageOptions.storage || this.storageOptions.storage;
  };

  private persistJWTTokenPayload = (payload: AuthPayload) => {
    this.storageOptions.storage.setItem(this.storageOptions.key, JSON.stringify(payload));
  };

  private tryOverrideTokenExpiration = (authPayload: AuthPayload, jwtPayload: jose.JWTPayload) => {
    if (authPayload.expiresIn) return;

    if (jwtPayload.exp) authPayload.expiresIn = jwtPayload.exp;
  };

  private ejectTriggeredInterceptors = () => {
    if (this.axiosInterceptorEjectIds.length === 0) return;

    this.axiosInterceptorEjectIds.forEach((id) => {
      this.axiosInstance?.interceptors.request.eject(id);
    });

    this.axiosInterceptorEjectIds = [];
  };
}

export { AuthConfig };
