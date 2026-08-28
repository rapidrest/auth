////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import axios, { AxiosResponse } from "axios";
import * as crypto from "crypto";
import jwt from "jsonwebtoken";
import { ApiError, type JWTUser } from "@rapidrest/core";
import { ApiErrors, AuthStrategy, HttpRequest, HttpResponse, AuthResult } from "@rapidrest/service-core";

export const Protocol = {
    OAUTH2: "oauth2",
    OPENID: "openid",
} as const;

/**
 * Describes an authenticated user profile as converted by an OAuth/OpenID provider that is ready to be
 * used by the system to create a local User and/or Profile.
 */
export interface OIDCProfile {
    /** The unique identifier of the user as registered with the provider. */
    id: string;
    /** The unique name of the provider. */
    provider: string;
    /** The alias or display name of the user. */
    alias?: string;
    /** The URL of the user's avatar image. */
    avatar?: string;
    /** The birthdate of the user. */
    birthdate?: string;
    /** The email address that the user registered their account with the provider. */
    email?: string;
    /** Indicates if the user email address has been verified by the provider. */
    email_verified?: boolean;
    /** The real surname name of the user. */
    familyName?: string;
    /** The real given name of the user. */
    givenName?: string;
    /** The user's chosen language option. */
    locale?: string;
    /** The phone number that the user registered their account with the provider. */
    phone?: string;
    /** Indicates if the user phone number has been verified by the provider. */
    phone_verified?: boolean;
    /** The unique name of the user. */
    username?: string;
}

/** The two PKCE code challenge methods registered by RFC 7636 / the IANA PKCE registry. */
export type PkceMethod = "S256" | "plain";

export interface OIDCProvider {
    /** The unique name of the provider that can be used for authentication. */
    name: string;
    /** The URL of the provider's API that will be used to perform authorization requests. */
    authorizationURL: string;
    /** The unique identifier that has been provided by the OIDC provider. */
    clientID: string;
    /** The shared secret that has been provided by the OIDC provider. */
    clientSecret: string;
    /**
     * Indicates whether PKCE is required by the OIDC provider. Set to `true` to allow either
     * `S256` or `plain` (the client may choose), or set to `"S256"`/`"plain"` to require that
     * specific method regardless of what the client requests.
     */
    pkce?: boolean | PkceMethod;
    /**
     * The default transformation map to use to convert the third-party profile data to an `OIDCProfile`.
     * Default is `DEFAULT_PROFILE_MAP`.
     * */
    profileMap?: any;
    /** The URL of the provider's API that the user profile can be retrieved from. */
    profileURL?: string;
    /** The authentication protocol to use (e.g. OIDC 2.0 or Open ID). */
    protocol: string;
    /**
     * The callback URI (or list of allowed callback URIs) that have been registered with the OIDC
     * provider. A caller may request a specific `redirect_uri` via query parameter, but only a value
     * that exactly matches one of these is honored — anything else is rejected.
     */
    redirectURI: string | string[];
    /** The list of scopes to request during the authentication process. Default is `none`. */
    scope?: string[];
    /** The URL of the provider's API that will perform token exchange. */
    tokenURL: string;
    /**
     * The provider's JWKS endpoint, used to verify ID token signatures. Required when `protocol`
     * is `openid` and the provider returns an `id_token`.
     */
    jwksURI?: string;
    /**
     * The expected `iss` claim of ID tokens from this provider. Required when `protocol` is
     * `openid` and the provider returns an `id_token`.
     */
    issuer?: string;
}

/**
 * Describes the configuration options that can be used to initialize OIDCStrategy.
 *
 * @author Jean-Philippe Steinmetz
 */
export class OIDCStrategyOptions {
    /** The unique name of the auth strategy instance. */
    public name: string = "oauth";

    /**
     * The configuration of the OIDC/OpenID provider.
     */
    public provider: OIDCProvider;

    /**
     * Retrieves the user data for the given unique identifier after authentication has completed successfully.
     * NOTE: You must override this function when using this strategy.
     * @param token The user's authenticated access token to the third-party provider.
     * @param profile The user's profile data associated with the third-party provider.
     */
    public getUser(token: string, profile: OIDCProfile): Promise<JWTUser | undefined> {
        throw new Error("Did you forget to override OIDCStrategyOptions.getUser?");
    }

    constructor(name: string, provider: OIDCProvider) {
        this.name = name;
        this.provider = provider;
    }
}

export const DEFAULT_PROFILE_MAP: any = {
    id: "profile.id",
    name: "profile.username",
    email: "profile.email",
    email_verified: "profile.verified && profile.email",
    givenName: "profile.givenName",
    familyName: "profile.familyName",
    birthdate: "profile.birthdate",
    locale: "profile.locale",
    phone: "profile.phone",
    phone_verified: "profile.verified && profile.phone",
    avatar: "profile.avatar",
};

/** Matches a valid RFC 7636 code_verifier: 43-128 chars from the unreserved character set. */
const PKCE_VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]{43,128}$/;

/**
 * Implements an authentication strategy for performing OIDC 2.0 or OpenID Connect (OIDC) authorization with a
 * third-party provider. This strategy does not require that require an account already be registered. When using
 * this strategy, ensure to allow for account creation to occur after a successful login.
 *
 * The authorization flow has the following steps:
 *
 * 1. Client initiates a request for an Authorization Request URI. Builds the Authorization Request URI and returns it
 * to the client.
 * 2. The client should automatically redirect the user to the Authorization Request URI obtained in step 1.
 * 3. Once the user has approved the authorization request with the third-party provider the client will be
 * redirected to the application's registered callback URL with a single query parameter containing an
 * Authorization Code. The client initiates a request to a route handler, containing the code, and then
 * calls `authenticate()`.
 *
 * NOTE: Requires session support!
 *
 * @author Jean-Philippe Steinmetz <rapidrests@gmail.com>
 */
export class OIDCStrategy implements AuthStrategy {
    public readonly name: string = "oauth";
    private options: OIDCStrategyOptions;
    /** Cached `jwks-rsa` clients, keyed by JWKS URI, so keys are cached across requests. */
    private jwksClients: Map<string, any> = new Map();

    constructor(options: OIDCStrategyOptions) {
        this.name = options.name ?? this.name;
        this.options = options;
    }

    /**
     * Resolves the effective PKCE code challenge method to use, given what the provider requires
     * (if anything specific) and what the client requested. Throws if the client requests an
     * invalid value, or a value that conflicts with a provider-mandated method.
     *
     * @param clientMethod The `code_challenge_method` requested by the client, if any.
     */
    protected resolvePkceMethod(clientMethod?: string): PkceMethod {
        const pkce = this.options.provider.pkce;
        const required: PkceMethod | undefined = pkce === "S256" || pkce === "plain" ? pkce : undefined;

        if (clientMethod) {
            if (clientMethod !== "S256" && clientMethod !== "plain") {
                throw new ApiError(
                    ApiErrors.INVALID_REQUEST,
                    400,
                    `Invalid code_challenge_method '${clientMethod}'. Must be "S256" or "plain".`,
                );
            }
            if (required && clientMethod !== required) {
                throw new ApiError(
                    ApiErrors.INVALID_REQUEST,
                    400,
                    `This provider requires PKCE method '${required}', but '${clientMethod}' was requested.`,
                );
            }
            return clientMethod;
        }

        return required ?? "S256";
    }

    /**
     * Creates and returns the Authorization Request URI for the configured OIDC provider.
     *
     * @param req The source HTTP request.
     * @param redirectURI The source URI to redirect the user to once authentication is complete.
     */
    protected buildAuthorizationURI(req: HttpRequest, redirectURI?: string): string {
        if (!req.session) {
            throw new ApiError(
                ApiErrors.INTERNAL_ERROR,
                500,
                "OIDCStrategy requires session support. Configure the `session` config block so the " +
                    "session middleware is registered.",
            );
        }

        const provider = this.options.provider;

        // Only a redirect_uri that exactly matches one of the provider's configured/allowed values
        // is honored — this lets a downstream frontend dynamically choose its own callback target
        // (different environments, subdomains, multi-tenant deployments) without opening the door
        // to an attacker supplying an arbitrary redirect_uri.
        const allowedRedirectURIs: string[] = Array.isArray(provider.redirectURI)
            ? provider.redirectURI
            : [provider.redirectURI];
        const requestedRedirectURI = redirectURI ?? (req.query?.redirect_uri as string | undefined);
        if (requestedRedirectURI && !allowedRedirectURIs.includes(requestedRedirectURI)) {
            throw new ApiError(
                ApiErrors.INVALID_REQUEST,
                400,
                `redirect_uri '${requestedRedirectURI}' is not in the list of allowed redirect URIs configured ` +
                    "for this provider.",
            );
        }
        const finalRedirectURI = requestedRedirectURI ?? allowedRedirectURIs[0];
        req.session.redirect_uri = finalRedirectURI;

        let url: string = provider.authorizationURL + `?client_id=${encodeURIComponent(provider.clientID)}`;

        // Combined state: a server-generated CSRF token, plus optional client-supplied
        // app-correlation data. The session cookie is httpOnly (invisible to browser JS), so this
        // is the only channel a frontend has to round-trip its own data through the provider
        // redirect. Only the CSRF-token half is ever validated server-side; the app-data half is
        // handed back to the caller untouched via AuthResult.state.
        const csrfToken: string = crypto.randomBytes(24).toString("base64url");
        const clientAppData: string = (req.query?.state as string | undefined) ?? "";
        req.session.state = csrfToken;
        url += `&state=${encodeURIComponent(`${csrfToken}.${clientAppData}`)}`;

        if (provider.pkce) {
            const method = this.resolvePkceMethod(req.query.code_challenge_method as string | undefined);
            const clientVerifier = req.query.code_verifier as string | undefined;
            if (clientVerifier && !PKCE_VERIFIER_PATTERN.test(clientVerifier)) {
                throw new ApiError(
                    ApiErrors.INVALID_REQUEST,
                    400,
                    "code_verifier does not meet RFC 7636 requirements (43-128 chars, unreserved charset).",
                );
            }
            const verifier: string = clientVerifier ?? crypto.randomBytes(32).toString("base64url");
            const codeChallenge: string =
                (req.query.code_challenge as string) ||
                (method === "plain"
                    ? verifier
                    : crypto
                          .createHash("sha256")
                          .update(Buffer.from(verifier, "ascii"))
                          .digest("base64")
                          .replace(/=/g, "")
                          .replace(/\+/g, "-")
                          .replace(/\//g, "_"));

            url += `&code_challenge=${encodeURIComponent(codeChallenge)}&code_challenge_method=${encodeURIComponent(method)}`;

            // Store all pkce info in the session for reference later.
            req.session.code_challenge = codeChallenge;
            req.session.code_challenge_method = method;
            req.session.code_verifier = verifier;
        }

        if (provider.protocol === Protocol.OPENID) {
            const nonce: string = crypto.randomBytes(24).toString("base64url");
            req.session.nonce = nonce;
            url += `&nonce=${encodeURIComponent(nonce)}`;
        }

        url += `&redirect_uri=${encodeURIComponent(finalRedirectURI)}`;
        url += `&response_type=code`;
        url += `&scope=${encodeURIComponent((req.query.scope as string) || (provider.scope ?? []).join(" "))}`;

        return url;
    }

    public async authenticate(
        req: HttpRequest,
        res: HttpResponse,
        required?: boolean,
    ): Promise<AuthResult | undefined> {
        const error = req.query?.error ?? req.body?.error;
        if (error) {
            const description = req.query?.error_description ?? req.body?.error_description;
            throw new ApiError(
                ApiErrors.AUTH_FAILED,
                401,
                `OIDC provider returned an error: ${error}${description ? ` - ${description}` : ""}`,
            );
        }

        // Is this an authorization request or token exchange?
        if (req.body?.code || req.query?.code) {
            if (!req.session) {
                throw new ApiError(
                    ApiErrors.INTERNAL_ERROR,
                    500,
                    "OIDCStrategy requires session support. Configure the `session` config block so the " +
                        "session middleware is registered.",
                );
            }

            const incomingState: string = (req.body?.state ?? req.query?.state ?? "") as string;
            const separatorIdx = incomingState.indexOf(".");
            const csrfPortion = separatorIdx >= 0 ? incomingState.slice(0, separatorIdx) : incomingState;
            const appData = separatorIdx >= 0 ? incomingState.slice(separatorIdx + 1) : undefined;

            const sessionState = req.session.state ?? "";
            const csrfBuf = Buffer.from(csrfPortion);
            const sessionBuf = Buffer.from(sessionState);
            const csrfValid =
                !!csrfPortion &&
                !!sessionState &&
                csrfBuf.length === sessionBuf.length &&
                crypto.timingSafeEqual(csrfBuf, sessionBuf);
            if (!csrfValid) {
                throw new Error("Invalid or missing state parameter. Possible CSRF attempt.");
            }
            delete req.session.state;

            // 1. First exchange the auth code for the access token with the provider
            const accessToken: any = await this.exchangeOIDCCode(req);

            // 2. Retrieve the user profile.
            const profile: any = await this.retrieveUserProfile(accessToken, req);

            // Consumed — clear so a stolen/replayed session cookie can't be used against a second flow.
            delete req.session.code_verifier;
            delete req.session.code_challenge;
            delete req.session.code_challenge_method;
            delete req.session.nonce;
            delete req.session.redirect_uri;

            // 3. Notify the verify callback to create a user object for this profile.
            const user: JWTUser | undefined = await this.options.getUser(accessToken, profile);

            return {
                data: accessToken,
                method: this.name,
                payload: accessToken,
                state: appData,
                user,
            };
        } else {
            const url: string = this.buildAuthorizationURI(req);
            res.status(302);
            res.setHeader("Location", url);
            res.setHeader("Content-Length", 0);
            res.end();
            return undefined;
        }
    }

    public authenticateSync(req: HttpRequest, res: HttpResponse, required?: boolean): AuthResult | undefined {
        throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, "Not supported. This auth strategy must be used asynchronously.");
    }

    /**
     * Performs a request against the OIDC provider to exchange the given authorization code for an access token.
     *
     * @param req The request data to use in the exchange exchange.
     * @param provider The OIDC provider to perform the exchange with.
     */
    protected async exchangeOIDCCode(req: HttpRequest): Promise<any> {
        const provider = this.options.provider;

        // The code may come from either request query for body
        const code: string = req.body?.code || req.query?.code;
        if (!code) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "Authorization code is missing!");
        }

        const allowedRedirectURIs: string[] = Array.isArray(provider.redirectURI)
            ? provider.redirectURI
            : [provider.redirectURI];

        // Create a url-encoded payload for the token exchange per RFC-6749 Section 4.1.3
        let data: any = {
            code,
            grant_type: "authorization_code",
            // Must exactly match what was sent during the authorize step — reuse the value that was
            // validated and stored in the session then, rather than re-trusting client input here.
            redirect_uri: req.session?.redirect_uri ?? allowedRedirectURIs[0],
        };

        // If PKCE is required for this provider make sure to include the challenge. The request body may have already
        // included the challenge details. If not, we'll use what we have from the stored session.
        if (provider.pkce) {
            data.code_verifier = req.body?.code_verifier ?? req.query?.code_verifier ?? req.session?.code_verifier;
        }

        const headers: any = { "Content-Type": "application/x-www-form-urlencoded" };
        if (provider.clientSecret) {
            headers.Authorization = `Basic ${Buffer.from(provider.clientID + ":" + provider.clientSecret).toString("base64")}`;
        } else {
            // Public/PKCE-only clients have no secret to authenticate with via Basic auth — per
            // RFC 6749 §2.3.1 they must instead identify themselves via a body parameter.
            data.client_id = provider.clientID;
        }

        try {
            const result: AxiosResponse = await axios.post(provider.tokenURL, data, { headers });
            if (result && (result.status !== 200 || !result.data)) {
                throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, "Failed to retrieve access token.");
            }

            const json: any = typeof result.data === "string" ? JSON.parse(result.data) : result.data;
            return json;
        } catch (err: any) {
            const error: any = err.response?.data || new Error(`Failed to exchange auth token. ${err.message || ""}`);
            error.status = err.status;
            throw error;
        }
    }

    /**
     * Converts the given user profile obtained from the specified OAuth provider into an OIDCProfile object.
     *
     * @param profile The profile to convert.
     * @param provider The OAuth provider that the profile was obtained from.
     */
    protected convertProfile(profile: any): OIDCProfile {
        const result: any = {
            provider: this.options.provider.name,
            _json: profile,
        };

        const transform = (profile, map, result) => {
            for (const key in map) {
                try {
                    if (typeof map[key] === "object") {
                        result[key] = transform(profile, map[key], Array.isArray(map[key]) ? [] : {});
                    } else {
                        // Note: The following eval() is intentional and by design. The map whose values will be
                        // executed here can only be set by the server configuration and/or system environment and
                        // is never exposed to a potential malicious client. Therefore, it is considered safe to
                        // run eval() here. Should the mechanism for obtaining the profile map change in the future
                        // then this should be flagged as a problem. Until then, ignore it.
                        // eslint-disable-next-line no-eval
                        result[key] = eval(map[key]);
                    }
                } catch (err) {
                    throw new ApiError(
                        ApiErrors.INTERNAL_ERROR,
                        500,
                        `Failed on transforming ${key} using mapped value ${map[key]}`,
                    );
                }
            }

            return result;
        };

        const map: any = Object.assign({}, DEFAULT_PROFILE_MAP, this.options.provider.profileMap);
        return transform(profile, map, result);
    }

    /**
     * Retrieves the user profile from the specified OIDC provider using the given access token.
     * @param token The access token to use to retrieve the user profile.
     * @param req The source HTTP request, used to validate the id_token's nonce claim.
     */
    protected async retrieveUserProfile(token: any, req: HttpRequest): Promise<OIDCProfile | undefined> {
        // Was an id_token provided? If so, we can verify and decode it to retrieve the profile
        // without having to contact the OIDC provider again — some OpenID providers only expose
        // profile data this way and have no separate profile endpoint at all.
        if (token.id_token && this.options.provider.protocol === Protocol.OPENID) {
            const payload = await this.verifyIdToken(token.id_token, req);
            return this.convertProfile(payload);
        }

        // If no profileURL has been set just immediately return.
        if (!this.options.provider.profileURL) {
            return undefined;
        }

        try {
            const request: AxiosResponse = await axios.get(this.options.provider.profileURL, {
                headers: {
                    Accept: "application/json",
                    Authorization: `${token.token_type} ${token.access_token}`,
                },
            });
            if (request && (request.status !== 200 || !request.data)) {
                throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, "Failed to retrieve user profile.");
            }

            const json: any = typeof request.data === "string" ? JSON.parse(request.data) : request.data;
            return this.convertProfile(json);
        } catch (err: any) {
            const error: any = err.response?.data || new Error(`Failed to retrieve user profile. ${err.message || ""}`);
            error.status = err.status;
            throw error;
        }
    }

    /**
     * Dynamically imports the given optional peer dependency, throwing a helpful error if it is not installed.
     *
     * @param pkg The name of the package to import.
     */
    private async importOptionalDependency(pkg: string): Promise<any> {
        try {
            return await import(pkg);
        } catch (err: any) {
            throw new ApiError(
                ApiErrors.INTERNAL_ERROR,
                500,
                `OIDC provider '${this.options.provider.name}' uses OpenID with an id_token, which requires ` +
                    `the optional peer dependency '${pkg}' for signature verification. Install it with: yarn add ${pkg}`,
            );
        }
    }

    /**
     * Returns a (cached) `jwks-rsa` client for the given JWKS URI.
     * @param jwksURI The JWKS endpoint to fetch signing keys from.
     */
    private async getJwksClient(jwksURI: string): Promise<any> {
        let client = this.jwksClients.get(jwksURI);
        if (!client) {
            const mod: any = await this.importOptionalDependency("jwks-rsa");
            /* v8 ignore next -- `jwks-rsa`'s CJS export always gets a synthetic `.default` under
               Node's ESM dynamic-import interop; this only guards atypical bundler/interop setups
               where it doesn't. */
            const buildClient = mod.default ?? mod;
            client = buildClient({ jwksUri: jwksURI });
            this.jwksClients.set(jwksURI, client);
        }
        return client;
    }

    /**
     * Verifies the signature, issuer, audience, and nonce of the given ID token.
     *
     * @param idToken The compact JWT id_token to verify.
     * @param req The source HTTP request, used to validate the nonce against the stored session value.
     */
    private async verifyIdToken(idToken: string, req: HttpRequest): Promise<any> {
        const provider = this.options.provider;
        if (!provider.jwksURI || !provider.issuer) {
            throw new ApiError(
                ApiErrors.INTERNAL_ERROR,
                500,
                `OIDC provider '${provider.name}' has protocol 'openid' but is missing required ` +
                    "'jwksURI'/'issuer' configuration for ID token verification.",
            );
        }

        const decoded = jwt.decode(idToken, { complete: true });
        if (!decoded || typeof decoded === "string") {
            throw new Error("Invalid id_token: unable to decode JWT header.");
        }

        const client = await this.getJwksClient(provider.jwksURI);
        const signingKey = await client.getSigningKey(decoded.header.kid);
        const publicKey: string = signingKey.getPublicKey();

        const payload: any = jwt.verify(idToken, publicKey, {
            algorithms: ["RS256"],
            issuer: provider.issuer,
            audience: provider.clientID,
        });

        if (!req.session?.nonce || payload.nonce !== req.session.nonce) {
            throw new Error("Invalid or missing nonce in id_token. Possible replay attack.");
        }

        return payload;
    }
}
