////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import type { JWTUser } from "@rapidrest/core";
import { AuthResult, AuthStrategy, HttpRequest, HttpResponse } from "@rapidrest/service-core";
import { getBasicData, getRequestData } from "./shared.js";

/**
 * Describes the configuration options that can be used to initialize BasicStrategy.
 *
 * @author Jean-Philippe Steinmetz
 */
export class BasicStrategyOptions {
    /** The name of the header to look for when performing header based authentication. Default value is `Authorization`. */
    public headerKey: string = "authorization";
    /** The authorization scheme type when using header based authentication. Default value is `jwt`. */
    public headerScheme: string = "basic";
    /** The name of the request query parameter to retrieve the token from when using query based authentication. Default value is `auth_basic`. */
    public queryKey: string = "auth_basic";
    /**
     * Set to `true` to allow credentials to be supplied via the `queryKey` URL parameter.
     * Disabled by default — query parameters appear in server logs, browser history, and
     * Referer headers, which permanently exposes credentials outside the application.
     */
    public allowQueryParam: boolean = false;
    /**
     * Optional hook invoked with the claimed identifier before credentials are verified. Implementations should
     * throw to reject the request once a caller-defined attempt threshold has been exceeded (see `RateLimiter`).
     * A no-op when not provided.
     */
    public checkRateLimit?(identifier: string, req: HttpRequest): Promise<void>;
    /**
     * The synchronous counterpart to `checkRateLimit`, invoked with the claimed identifier before
     * `verifySync` runs. This exists because `authenticateSync`/`verifySync` are used from contexts (e.g.
     * a WebSocket upgrade handshake) that cannot await a promise, so the normal Redis/async-backed
     * `RateLimiter` can't be used here — implementations that supply `verifySync` should also supply this
     * hook (e.g. backed by an in-memory counter) if brute-force protection is required on this path.
     * Implementations should throw to reject the request once an attempt threshold has been exceeded. A
     * no-op when not provided.
     */
    public checkRateLimitSync?(identifier: string, req: HttpRequest): void;
    /** Override this function to handle asynchronous (non-blocking) verification of the login info. */
    public verify(uid: string, secret: string): JWTUser | Promise<JWTUser | undefined> | undefined {
        throw new Error("Did you forget to override BasicStrategyOptions.verify?");
    }
    /** Override this function to handle synchronous (blocking) verification of the login info. */
    public verifySync(uid: string, secret: string): JWTUser | undefined {
        throw new Error("Did you forget to override BasicStrategyOptions.verifySync?");
    }
}

/**
 * Implements an authentication strategy that performs basic id and password authentication. This strategy requires an
 * existing user account to have already registered a valid password that will be validated. The strategy does not
 * implement how that password is to be validated or stored.
 *
 * @author Jean-Philippe Steinmetz <rapidrests@gmail.com>
 */
export class BasicStrategy implements AuthStrategy {
    public readonly name: string = "basic";
    private options: BasicStrategyOptions;

    constructor(options: BasicStrategyOptions = new BasicStrategyOptions()) {
        this.options = options;
    }

    public async authenticate(
        req: HttpRequest,
        res: HttpResponse,
        required?: boolean,
    ): Promise<AuthResult | undefined> {
        let { data, payload } = getRequestData(req);

        // If the login info has been found, verify it.
        if (payload.id && payload.password) {
            if (this.options.checkRateLimit) {
                await this.options.checkRateLimit(payload.id, req);
            }
            const user: JWTUser | undefined = await this.options.verify(payload.id, payload.password);
            if (user) {
                return {
                    data,
                    method: this.name,
                    payload,
                    user,
                };
            }
        }

        if (required) {
            throw new Error("Invalid authorization request.");
        }

        return undefined;
    }

    public authenticateSync(req: HttpRequest, res: HttpResponse, required?: boolean): AuthResult | undefined {
        let { data, payload } = getRequestData(req);

        // If the login info has been found, verify it.
        if (payload.id && payload.password) {
            if (this.options.checkRateLimitSync) {
                this.options.checkRateLimitSync(payload.id, req);
            }
            const user: JWTUser | undefined = this.options.verifySync(payload.id, payload.password);
            if (user) {
                return {
                    data,
                    method: this.name,
                    payload,
                    user,
                };
            }
        }

        if (required) {
            throw new Error("Invalid authorization request.");
        }

        return undefined;
    }
}
