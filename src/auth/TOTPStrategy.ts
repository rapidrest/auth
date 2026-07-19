////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import type { JWTUser } from "@rapidrest/core";
import { AuthResult, AuthStrategy, HttpRequest, HttpResponse } from "@rapidrest/service-core";
import { getRequestData, verifyTOTP } from "./shared.js";
import { TOTPSecret } from "./types.js";

/**
 * Describes the configuration options that can be used to initialize TOTPStrategy.
 *
 * @author Jean-Philippe Steinmetz
 */
export class TOTPStrategyOptions {
    /** The name of the header to look for when performing header based authentication. Default value is `Authorization`. */
    public headerKey: string = "authorization";
    /** The authorization scheme type when using header based authentication. Default value is `jwt`. */
    public headerScheme: string = "totp";
    /** The name of the request query parameter to retrieve the token from when using query based authentication. Default value is `auth_totp`. */
    public queryKey: string = "auth_totp";
    /**
     * Set to `true` to allow credentials to be supplied via the `queryKey` URL parameter.
     * Disabled by default — query parameters appear in server logs, browser history, and
     * Referer headers, which permanently exposes credentials outside the application.
     */
    public allowQueryParam: boolean = false;
    /**
     * Retrieves the stored TOTP secrets for the user with the given unique identifier.
     * NOTE: You must override this function when using this strategy.
     * @param id The unique identifier of the user.
     */
    public getSecrets(uid: string): Promise<TOTPSecret[]> {
        throw new Error("Did you forget to override TOTPStrategyOptions.getSecrets?");
    }
    /**
     * Retrieves the user data for the given unique identifier.
     * NOTE: You must override this function when using this strategy.
     * @param id The unique id of the user that has been successfully authenticated.
     */
    public getUser(id: string): Promise<JWTUser | undefined> {
        throw new Error("Did you forget to override TOTPStrategyOptions.getUser?");
    }
}

/**
 * Implements an authentication strategy that performs Time-Based One Time Password authentication. This strategy
 * requires an existing user account to have already registered a TOTP secret that will be validated. The strategy does
 * not implement how that secret is to be stored.
 *
 * @author Jean-Philippe Steinmetz <rapidrests@gmail.com>
 */
export class TOTPStrategy implements AuthStrategy {
    public readonly name: string = "totp";
    private options: TOTPStrategyOptions;

    constructor(options: TOTPStrategyOptions = new TOTPStrategyOptions()) {
        this.options = options;
    }

    public async authenticate(
        req: HttpRequest,
        res: HttpResponse,
        required?: boolean,
    ): Promise<AuthResult | undefined> {
        const { data, payload } = getRequestData(req, this.options.headerKey, this.options.headerScheme);

        const user: JWTUser | undefined = await this.verify(payload);
        if (user) {
            return {
                data,
                method: this.name,
                payload,
                user,
            };
        }

        if (required) {
            throw new Error("Invalid authentiation request.");
        }

        return undefined;
    }

    public authenticateSync(req: HttpRequest, res: HttpResponse, required?: boolean): AuthResult | undefined {
        throw new Error("Not supported. This auth strategy must be used asynchronously.");
    }

    protected async verify(payload: any): Promise<JWTUser | undefined> {
        const user: JWTUser | undefined = await this.options.getUser(payload.id);

        if (user) {
            const secret: TOTPSecret[] = await this.options.getSecrets(user.uid);

            if (secret) {
                let result: any = await verifyTOTP(payload.token, secret);
                if (result && result.valid) {
                    return user;
                }
            }
        }

        return undefined;
    }
}
