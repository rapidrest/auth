///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import "reflect-metadata";
import * as crypto from "crypto";
import { ApiError, JWTUtils, JWTUtilsConfig, ObjectDecorators } from "@rapidrest/core";
import {
    ApiErrors,
    AuthMiddleware,
    DocDecorators,
    HttpRequest,
    HttpResponse,
    ObjectFactory,
    RepoUtils,
    RouteDecorators,
} from "@rapidrest/service-core";
import parseDuration from "parse-duration";
import { AuthorizationCode, Client, ConsentGrant } from "../models/types.js";
import { hashOpaqueToken } from "../auth/shared.js";

const { Config, Init, Inject } = ObjectDecorators;
const { Summary, Description, Returns } = DocDecorators;
const { Get, Post, Request, Response } = RouteDecorators;

/** The claim name embedded in a consent ticket to distinguish it from any other token this deployment signs. */
const CONSENT_TICKET_TYPE = "oauth_consent";

/**
 * Handles the OAuth 2.0 / OIDC `/authorize` endpoint (RFC 6749 §4.1.1) and the consent decision that may
 * follow it. Every response is JSON — never a raw HTTP redirect — since this library never owns real HTTP
 * routing/rendering; a subclass mounted by the downstream project decides how to actually navigate the
 * browser based on the `redirectTo`/`loginRequired`/`consentRequired` shape returned.
 *
 * Deliberately does not authenticate the resource owner via a fixed `@Auth([...])` decorator (a decorator's
 * strategy list is fixed at class-declaration time — see the caveat documented on `BaseAuthOIDCRoute`).
 * Instead, `resolveUserUid()` first checks `req.session.userUid` (the field `TokenUtils.createAuthResult()`
 * already populates for every existing login strategy, including the OIDC relying-party flow against an
 * upstream IdP), falling back to `authMiddleware.authenticate(resourceOwnerStrategies, ...)` only when no
 * session is present. This is what lets a mobile app federate through an upstream IdP (e.g. Entra ID) with
 * zero changes to this library's relying-party code — the user simply logs in via the existing OIDC route
 * first, and `/authorize` observes the resulting session.
 *
 * Consent has no server-side ephemeral storage: when consent is required, a short-lived, HMAC-signed
 * "consent ticket" (via `JWTUtils`, sharing this deployment's existing `auth:secret`) encodes the pending
 * request, and `decideConsent()` verifies and decodes it — avoiding a second storage dependency (Redis/
 * memory) for state that's inherently short-lived and only ever round-tripped through the caller.
 *
 * Honors the OIDC Core §3.1.2.1 `prompt` request parameter: `none` demands zero user interaction, failing
 * fast with a `login_required`/`consent_required` error redirect instead of the usual
 * `{loginRequired:true}`/`{consentRequired:true}` (which invite the downstream app to interact with the
 * user) whenever either would otherwise be needed; `login`/`select_account` force fresh interactive login
 * even when a session already resolves a user (this library has no concept of an account picker, so both
 * collapse to the same "log in again" signal); `consent` forces the consent screen even when a sufficient
 * `ConsentGrant` already exists. `none` MUST NOT be combined with any other value (RFC-mandated), and is
 * rejected with `invalid_request` if it is.
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseOAuthAuthorizeRoute<C extends Client, A extends AuthorizationCode, G extends ConsentGrant> {
    protected abstract authorizationCodeClass: any;
    protected abstract clientClass: any;
    protected abstract consentGrantClass: any;

    // Automatically injected by ObjectFactory on instantiation
    private _objectFactory?: ObjectFactory;

    @Inject(AuthMiddleware)
    protected authMiddleware?: AuthMiddleware;

    protected authorizationCodeRepo?: RepoUtils<A>;

    protected clientRepo?: RepoUtils<C>;

    @Config("auth:oauth_server:codeTTL", "60s")
    protected codeTTL: string = "60s";

    @Config("auth:oauth_server:consentTicketTTL", "10m")
    protected consentTicketTTL: string = "10m";

    protected consentGrantRepo?: RepoUtils<G>;

    @Config("auth")
    protected jwtConfig?: any;

    /**
     * The list of strategy names (registered on `AuthMiddleware`) to attempt when no `req.session.userUid`
     * is present — e.g. `["jwt"]`, or `["jwt", "oidc_entra"]` for a deployment federating through an
     * upstream IdP. A subclass must supply this.
     */
    protected abstract resourceOwnerStrategies: string[];

    /**
     * Called on server startup to initialize the route with any defaults.
     */
    @Init
    private async initialize(): Promise<void> {
        if (!this._objectFactory) {
            throw new Error("objectFactory is not set.");
        }

        if (!this.clientRepo && this.clientClass) {
            this.clientRepo = await this._objectFactory.newInstance(RepoUtils, {
                name: this.clientClass.name,
                args: [this.clientClass],
            });
        }

        if (!this.authorizationCodeRepo && this.authorizationCodeClass) {
            this.authorizationCodeRepo = await this._objectFactory.newInstance(RepoUtils, {
                name: this.authorizationCodeClass.name,
                args: [this.authorizationCodeClass],
            });
        }

        if (!this.consentGrantRepo && this.consentGrantClass) {
            this.consentGrantRepo = await this._objectFactory.newInstance(RepoUtils, {
                name: this.consentGrantClass.name,
                args: [this.consentGrantClass],
            });
        }
    }

    /**
     * Resolves the uid of the currently authenticated resource owner, or `undefined` if there isn't one.
     * See the class doc comment for why this doesn't use a fixed `@Auth([...])` decorator.
     */
    protected async resolveUserUid(req: HttpRequest, res: HttpResponse): Promise<string | undefined> {
        if (typeof req.session?.userUid === "string") {
            return req.session.userUid;
        }
        const result = await this.authMiddleware?.authenticate(this.resourceOwnerStrategies, req, res, false);
        return result?.user?.uid;
    }

    /** Builds the signing/verification config for a consent ticket — this deployment's shared `auth:secret`,
     * deliberately without the `audience`/`issuer` constraints `auth:options` applies to this app's own
     * relying-party tokens, since a consent ticket is an unrelated, purely internal artifact. */
    private ticketConfig(expiresIn?: number): JWTUtilsConfig {
        const options: any = expiresIn !== undefined ? { expiresIn } : {};
        return { secret: this.jwtConfig.secret, options };
    }

    private async createConsentTicket(data: Record<string, any>): Promise<string> {
        const expiresIn: number = parseDuration(this.consentTicketTTL, "sec") || 600;
        return JWTUtils.createToken(this.ticketConfig(expiresIn), { uid: data.userUid, roles: [], scopes: [] }, {
            typ: CONSENT_TICKET_TYPE,
            ...data,
        });
    }

    private async verifyConsentTicket(ticket: string): Promise<any> {
        const payload: any = await JWTUtils.decodeToken(this.ticketConfig(), ticket);
        if (payload.typ !== CONSENT_TICKET_TYPE) {
            throw new Error("Not a consent ticket.");
        }
        return payload;
    }

    /** Returns the caller's existing `ConsentGrant` for `clientId` if it already covers every scope in
     * `scope`, otherwise `undefined` (either no grant exists yet, or it doesn't cover everything requested). */
    /** Looks up this user's `ConsentGrant` for `clientId`, if any. Deliberately queries by `userUid` alone and
     * filters by `clientId` here in application code, rather than `find({userUid, clientId})`: `@rapidrest/
     * service-core`'s query builder coerces a plain string query value into a `Date` whenever `new
     * Date(value)` happens to parse without throwing — astonishingly lenient for a value like `"web-app-1"`
     * — which silently turns an exact-match `clientId` filter into one that can never match any row. `userUid`
     * (a uuid) never collides with this, so it's safe to filter on directly. */
    private async findExistingGrant(userUid: string, clientId: string): Promise<G | undefined> {
        // `skipCache: true` — the query-result cache is not invalidated when a new `ConsentGrant` is created
        // for the same `userUid`, so a request shortly after the very first one for that user would otherwise
        // keep reading a stale, now-incorrect result.
        const candidates = await this.consentGrantRepo!.find({ userUid }, { ignoreACL: true, skipCache: true });
        return candidates.find((g) => g.clientId === clientId);
    }

    private async findSufficientConsent(userUid: string, clientId: string, scope: string[]): Promise<G | undefined> {
        const grant = await this.findExistingGrant(userUid, clientId);
        if (!grant) {
            return undefined;
        }
        const grantedScopes = new Set(grant.scope.split(" ").filter(Boolean));
        return scope.every((s) => grantedScopes.has(s)) ? grant : undefined;
    }

    private async upsertConsentGrant(userUid: string, clientId: string, scope: string[]): Promise<void> {
        const existing = await this.findExistingGrant(userUid, clientId);
        if (existing) {
            const merged = new Set(existing.scope.split(" ").filter(Boolean));
            scope.forEach((s) => merged.add(s));
            await this.consentGrantRepo!.update(
                {
                    uid: existing.uid,
                    version: existing.version,
                    scope: Array.from(merged).join(" "),
                    lastUsedAt: new Date(),
                } as Partial<G>,
                existing,
                { ignoreACL: true },
            );
        } else {
            await this.consentGrantRepo!.create(
                { userUid, clientId, scope: scope.join(" "), grantedAt: new Date() } as Partial<G>,
                { ignoreACL: true },
            );
        }
    }

    /** Issues a new `AuthorizationCode` and returns the full `redirect_uri` (with `code`/`state`) to send
     * the resource owner's browser back to. */
    private async issueCode(
        client: C,
        userUid: string,
        redirectUri: string,
        scope: string[],
        codeChallenge: string | undefined,
        codeChallengeMethod: "S256" | "plain" | undefined,
        nonce: string | undefined,
        state: string | undefined,
    ): Promise<string> {
        const raw: string = crypto.randomBytes(32).toString("base64url");
        const expiresAt = new Date(Date.now() + (parseDuration(this.codeTTL, "sec") || 60) * 1000);

        await this.authorizationCodeRepo!.create(
            {
                codeHash: hashOpaqueToken(raw),
                clientId: client.uid,
                userUid,
                redirectUri,
                scope: scope.join(" "),
                codeChallenge,
                codeChallengeMethod,
                nonce,
                expiresAt,
                used: false,
            } as Partial<A>,
            { ignoreACL: true },
        );

        const url = new URL(redirectUri);
        url.searchParams.set("code", raw);
        if (state) {
            url.searchParams.set("state", state);
        }
        return url.toString();
    }

    /** Builds a `{redirectTo}` response carrying an RFC 6749 §4.1.2.1 error, for a request whose
     * `redirect_uri` has already been validated against the client's allow-list. */
    private buildErrorRedirect(redirectUri: string, state: string | undefined, error: string, description?: string) {
        const url = new URL(redirectUri);
        url.searchParams.set("error", error);
        if (description) {
            url.searchParams.set("error_description", description);
        }
        if (state) {
            url.searchParams.set("state", state);
        }
        return { redirectTo: url.toString() };
    }

    /**
     * Validates an incoming authorization request and either issues a code, or reports that a login or a
     * consent decision is needed first. `client_id`/`redirect_uri` validation failures are reported
     * directly (RFC 6749 §4.1.2.1 forbids redirecting anywhere before `redirect_uri` is trusted); every
     * other error is delivered *to* `redirect_uri` instead.
     */
    @Summary("OAuth 2.0 authorization endpoint")
    @Description(
        "Validates an OAuth 2.0 / OIDC authorization request. Returns `{loginRequired:true}` if the caller " +
            "isn't authenticated, `{consentRequired:true, requestId, client}` if consent is needed, or " +
            "`{redirectTo}` once an authorization code has been issued.",
    )
    @Returns([Object])
    @Get()
    public async authorize(@Request req: HttpRequest, @Response res: HttpResponse): Promise<any> {
        const query: Record<string, any> = req.query ?? {};
        const asString = (v: any): string | undefined => (typeof v === "string" ? v : undefined);

        const responseType = asString(query.response_type);
        const clientId = asString(query.client_id);
        const redirectUri = asString(query.redirect_uri);
        const requestedScope = asString(query.scope) ?? "";
        const state = asString(query.state);
        const codeChallenge = asString(query.code_challenge);
        const codeChallengeMethodParam = asString(query.code_challenge_method);
        const nonce = asString(query.nonce);
        const promptValues: string[] = (asString(query.prompt) ?? "").split(" ").filter(Boolean);

        if (!clientId) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "Missing required parameter: client_id.");
        }

        const client: C | undefined = await this.clientRepo!.findOne(clientId, { ignoreACL: true });
        if (!client || client.disabled) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "Unknown or disabled client_id.");
        }

        if (!redirectUri || !client.redirectUris.includes(redirectUri)) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "redirect_uri is missing or not registered for this client.");
        }

        // From here on `redirectUri` is trusted (an exact match against the client's registered allow-list)
        // — every further validation failure is reported *to* it rather than thrown directly.
        if (responseType !== "code") {
            return this.buildErrorRedirect(redirectUri, state, "unsupported_response_type", `Unsupported response_type: "${responseType}".`);
        }

        if (client.requirePkce && !codeChallenge) {
            return this.buildErrorRedirect(redirectUri, state, "invalid_request", "code_challenge is required for this client.");
        }

        let codeChallengeMethod: "S256" | "plain" | undefined;
        if (codeChallenge) {
            if (codeChallengeMethodParam !== undefined && codeChallengeMethodParam !== "S256" && codeChallengeMethodParam !== "plain") {
                return this.buildErrorRedirect(
                    redirectUri,
                    state,
                    "invalid_request",
                    `Invalid code_challenge_method: "${codeChallengeMethodParam}".`,
                );
            }
            codeChallengeMethod = codeChallengeMethodParam === "S256" ? "S256" : "plain";
        }

        // OIDC Core §3.1.2.1: `none` MUST NOT be combined with any other `prompt` value.
        if (promptValues.includes("none") && promptValues.length > 1) {
            return this.buildErrorRedirect(redirectUri, state, "invalid_request", "prompt=none must not be combined with other prompt values.");
        }

        const clientScopes = new Set(client.scope ? client.scope.split(" ").filter(Boolean) : []);
        const scope: string[] = requestedScope.split(" ").filter((s) => s && clientScopes.has(s));

        // `login`/`select_account` demand fresh, active interaction — never silently reuse an existing
        // session — so the session-based fast path in `resolveUserUid()` is deliberately skipped entirely
        // rather than merely double-checked, forcing the same `{loginRequired:true}` (or, under `none`,
        // `login_required`) outcome a genuinely unauthenticated caller would get.
        const forceLogin = promptValues.includes("login") || promptValues.includes("select_account");
        const userUid: string | undefined = forceLogin ? undefined : await this.resolveUserUid(req, res);
        if (!userUid) {
            if (promptValues.includes("none")) {
                return this.buildErrorRedirect(redirectUri, state, "login_required");
            }
            return { loginRequired: true };
        }

        // `consent` demands the consent screen even when a sufficient grant already exists.
        const forceConsent = promptValues.includes("consent");
        const sufficientGrant: G | undefined =
            client.firstParty || forceConsent ? undefined : await this.findSufficientConsent(userUid, client.uid, scope);

        if (!client.firstParty && !sufficientGrant) {
            if (promptValues.includes("none")) {
                return this.buildErrorRedirect(redirectUri, state, "consent_required");
            }
            const requestId = await this.createConsentTicket({
                clientId: client.uid,
                userUid,
                redirectUri,
                scope: scope.join(" "),
                codeChallenge,
                codeChallengeMethod,
                nonce,
                state,
            });
            return {
                consentRequired: true,
                requestId,
                client: { clientName: client.clientName, logoUri: client.logoUri, scope: scope.join(" ") },
            };
        }

        if (sufficientGrant) {
            await this.consentGrantRepo!.update(
                { uid: sufficientGrant.uid, version: sufficientGrant.version, lastUsedAt: new Date() } as Partial<G>,
                sufficientGrant,
                { ignoreACL: true },
            );
        }

        const redirectTo = await this.issueCode(client, userUid, redirectUri, scope, codeChallenge, codeChallengeMethod, nonce, state);
        return { redirectTo };
    }

    /**
     * Completes a pending consent decision produced by `authorize()`. On approval, records/updates the
     * `ConsentGrant` and issues an authorization code; on denial, returns an `access_denied` error redirect.
     * Requires the caller to be authenticated as the same user the ticket was issued to.
     */
    @Summary("OAuth 2.0 consent decision")
    @Description(
        "Completes a pending consent decision: on approval, records consent and issues an authorization " +
            "code; on denial, returns an access_denied error redirect. Never renders any UI.",
    )
    @Returns([Object])
    @Post("consent")
    public async decideConsent(@Request req: HttpRequest, @Response res: HttpResponse): Promise<any> {
        const { payload } = req.body && typeof req.body === "object" ? { payload: req.body } : { payload: undefined };
        const ticketRaw: string | undefined = payload?.requestId;
        const approved: boolean = payload?.approved === true;
        const scopeOverride: string[] | undefined = Array.isArray(payload?.scope) ? payload.scope : undefined;

        if (!ticketRaw) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "Missing required parameter: requestId.");
        }

        const userUid = await this.resolveUserUid(req, res);
        if (!userUid) {
            throw new ApiError(ApiErrors.AUTH_REQUIRED, 401, "Authentication is required to complete this request.");
        }

        let ticket: any;
        try {
            ticket = await this.verifyConsentTicket(ticketRaw);
        } catch (err) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "requestId is invalid or has expired.");
        }

        if (ticket.userUid !== userUid) {
            throw new ApiError(
                ApiErrors.AUTH_PERMISSION_FAILURE,
                403,
                "This consent request does not belong to the current user.",
            );
        }

        const client: C | undefined = await this.clientRepo!.findOne(ticket.clientId, { ignoreACL: true });
        if (!client || client.disabled) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "Unknown or disabled client_id.");
        }

        if (!approved) {
            return this.buildErrorRedirect(ticket.redirectUri, ticket.state, "access_denied", "The resource owner denied the request.");
        }

        const originalScope: string[] = ticket.scope ? ticket.scope.split(" ").filter(Boolean) : [];
        // Never grant more than was originally offered on the consent screen — down-select only.
        const grantedScope: string[] = scopeOverride ? originalScope.filter((s) => scopeOverride.includes(s)) : originalScope;

        await this.upsertConsentGrant(userUid, client.uid, grantedScope);

        const redirectTo = await this.issueCode(
            client,
            userUid,
            ticket.redirectUri,
            grantedScope,
            ticket.codeChallenge,
            ticket.codeChallengeMethod,
            ticket.nonce,
            ticket.state,
        );

        return { redirectTo };
    }
}
