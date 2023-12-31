import { AxiosError, AxiosInstance } from "axios";
import jwt from "jsonwebtoken";
import createAuthRefreshInterceptor from "axios-auth-refresh";

type LoggerMode = "log" | "error" | "warn";

type AuthCustomLogger = {
  [key in LoggerMode]: (...data: any[]) => void;
};

type TypeDefaultAsNull<T> = T | null;

type AuthStorageOptions = {
  key?: string;
  storage?: Storage;
};

type AuthPayload = {
  accessToken: string;
  refreshToken: string;
  expiresIn?: number;
};

type AuthConfigOptions = {
  authorize: <T extends User>(user: T) => Promise<AuthPayload>;
  signOutCallback?: () => Promise<void>;
  storageOptions?: AuthStorageOptions;
  customLogger?: AuthCustomLogger;
  scope?: string;
};

type User = {
  [key: string]: any;
  sub: string;
};

type ExtendUser<T extends Record<string, any>> = Omit<T, "sub"> & User;

class AuthLogger {
  public logger: AuthCustomLogger;

  constructor(customLogger?: AuthCustomLogger) {
    const logger: AuthCustomLogger = {
      log: (customLogger ?? console)["log"],
      warn: (customLogger ?? console)["warn"],
      error: (customLogger ?? console)["error"],
    };

    this.logger = logger;
  }
}

class AuthConfig extends AuthLogger {
  private authorize: AuthConfigOptions["authorize"];
  private signOutCallback: AuthConfigOptions["signOutCallback"];
  private storageOptions: Required<AuthStorageOptions> = { key: "token", storage: localStorage };
  private user: TypeDefaultAsNull<User> = null;
  private authPayload: TypeDefaultAsNull<AuthPayload> = null;
  private axiosInstance: TypeDefaultAsNull<AxiosInstance> = null;
  private axiosInterceptorEjectIds: number[] = [];

  constructor({ authorize, signOutCallback, scope, customLogger, storageOptions }: AuthConfigOptions) {
    super(customLogger);

    this.authorize = authorize;
    this.signOutCallback = signOutCallback;

    if (storageOptions) this.setStorageOptions(storageOptions, scope);
  }

  public async signIn<T extends User>(user: T) {
    try {
      const payload = await this.authorize(user);

      if (!payload) {
        this.logger.error("The authorize callback returns some invalid data");

        return;
      }

      await this.setUser(payload);

      this.user = user;

      this.logger.log("The user has beed successfully signed in");
    } catch (error) {
      this.logger.error(error);

      this.storageOptions.storage.removeItem(this.storageOptions.key);
    }
  }

  public setUser(payload: AuthPayload) {
    return new Promise<void>((resolve, reject) => {
      try {
        this.authPayload = payload;

        this.persistJWTTokenPayload(payload);

        resolve();

        this.logger.log("The user payload has been successfully updated.");
      } catch (error) {
        this.logger.error(error);

        reject(error);
      }
    });
  }

  public getUser<T extends Record<string, any>>() {
    return new Promise<TypeDefaultAsNull<ExtendUser<T>>>((resolve, reject) => {
      try {
        const token = this.storageOptions.storage.getItem(this.storageOptions.key);

        if (token === null) return resolve(null);

        return resolve(this.user as ExtendUser<T>);
      } catch (error) {
        this.logger.error(error);

        reject(error);
      }
    });
  }

  public async checkAccessTokenIsExpired(handleRefreshToken: (refreshToken: string) => Promise<AuthPayload>) {
    if (!this.authPayload || !this.authPayload.accessToken) return;

    const decodedToken = jwt.decode(this.authPayload.accessToken, { complete: true });

    if (decodedToken === null) return;

    this.tryOverrideTokenExpiration(this.authPayload, decodedToken.payload);

    if (this.authPayload.expiresIn && Date.now() > this.authPayload.expiresIn) {
      try {
        const newPayload = await handleRefreshToken(this.authPayload.refreshToken);

        await this.setUser(newPayload);
      } catch (error) {
        this.logger.error(error);

        this.ejectTriggeredInterceptors();
        this.storageOptions.storage.removeItem(this.storageOptions.key);
        this.user = null;
      }
    }
  }

  public async signOut() {
    this.storageOptions.storage.removeItem(this.storageOptions.key);

    this.user = null;

    this.ejectTriggeredInterceptors();

    if (this.signOutCallback) await this.signOutCallback();
  }

  public applyAxiosMiddleware(instance: AxiosInstance) {
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
          this.logger.error(error);

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
      }, this.logger.error)
    );
  }

  private setStorageOptions(storageOptions: AuthStorageOptions, scope?: string) {
    const key = storageOptions.key || this.storageOptions.key;

    this.storageOptions.key = scope ? scope + ":" + key : key;

    this.storageOptions.storage = storageOptions.storage || this.storageOptions.storage;
  }

  private persistJWTTokenPayload(payload: AuthPayload) {
    this.storageOptions.storage.setItem(this.storageOptions.key, JSON.stringify(payload));
  }

  private tryOverrideTokenExpiration(authPayload: AuthPayload, jwtPayload: string | jwt.JwtPayload) {
    if (typeof jwtPayload === "string" || authPayload.expiresIn) return;

    if (jwtPayload.exp) {
      authPayload.expiresIn = jwtPayload.exp;
    }
  }

  private ejectTriggeredInterceptors() {
    if (this.axiosInterceptorEjectIds.length === 0) return;

    this.axiosInterceptorEjectIds.forEach((id) => {
      if (!this.axiosInstance) return;

      this.axiosInstance.interceptors.request.eject(id);
    });

    this.axiosInterceptorEjectIds = [];
  }
}

export { AuthConfig };
