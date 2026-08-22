////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { ApiError, type JWTUser } from "@rapidrest/core";
import { ApiErrors, AuthResult, AuthStrategy, HttpRequest, HttpResponse } from "@rapidrest/service-core";
import { getRequestData, verifyDummyTOTP, verifyTOTP } from "./shared.js";
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
     * Optional hook invoked with the claimed identifier before the TOTP token is verified. Implementations
     * should throw to reject the request once a caller-defined attempt threshold has been exceeded (see
     * `RateLimiter`). A no-op when not provided.
     */
    public checkRateLimit?(identifier: string, req: HttpRequest): Promise<void>;
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
    /**
     * Persists the given time step as the last one successfully used for the identified secret, so
     * a captured/replayed token within its validity window can't be used to authenticate a second
     * time. Optional — when omitted, successfully-verified TOTP codes remain valid for reuse until
     * they naturally expire.
     * @param uid The unique id of the stored secret (as attached by `getSecrets()`) that was verified.
     * @param timeStep The RFC 6238 time step at which the token was verified.
     */
    public updateSecretTimeStep?(uid: string, timeStep: number): Promise<void>;
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

        if (payload.id && this.options.checkRateLimit) {
            await this.options.checkRateLimit(payload.id, req);
        }

        const user: JWTUser | undefined = await this.verify(payload, req);
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
        throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, "Not supported. This auth strategy must be used asynchronously.");
    }

    protected async verify(payload: any, req?: HttpRequest): Promise<JWTUser | undefined> {
        const user: JWTUser | undefined = await this.options.getUser(payload.id);
        const secrets: TOTPSecret[] = (user ? await this.options.getSecrets(user.uid) : []) ?? [];

        if (!user || secrets.length === 0) {
            // Burn an equivalent amount of time to the real verification path below so a
            // nonexistent user, or one with no registered TOTP secret, can't be distinguished from
            // a wrong code via response timing.
            await verifyDummyTOTP(payload.token);
            return undefined;
        }

        const result: any = await verifyTOTP(payload.token, secrets);
        if (result && result.valid) {
            if (result.uid && this.options.updateSecretTimeStep) {
                await this.options.updateSecretTimeStep(result.uid, result.timeStep);
            }
            return user;
        }

        return undefined;
    }
}
