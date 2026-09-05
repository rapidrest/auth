///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import "reflect-metadata";
import { ObjectDecorators } from "@rapidrest/core";
import { DocDecorators, HttpResponse, ObjectFactory, RouteDecorators } from "@rapidrest/service-core";

const { Config, Init } = ObjectDecorators;
const { Summary, Description, Returns } = DocDecorators;
const { Get, Response } = RouteDecorators;

/**
 * The absolute, final URLs of this deployment's other OAuth/OIDC endpoints — the one piece of information
 * only the downstream app mounting these routes actually knows (this library has no fixed route paths of
 * its own; see every other `Base*Route`'s class doc comment). `userinfo`/`revocation`/`introspection`/
 * `registration` are optional so a deployment that hasn't mounted one of those routes yet (e.g. before
 * dynamic client registration is wired up) still produces valid, spec-compliant metadata that simply omits
 * the corresponding `*_endpoint` field.
 */
export interface OAuthDiscoveryEndpoints {
    authorization: string;
    token: string;
    jwks: string;
    userinfo?: string;
    revocation?: string;
    introspection?: string;
    registration?: string;
}

/**
 * Serves this authorization server's discovery metadata (RFC 8414 "OAuth 2.0 Authorization Server Metadata"
 * and OIDC Discovery §3, which define the same JSON document shape) at whatever path(s) a subclass mounts
 * it to — typically both `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration`,
 * which a single mounted instance of this route can serve simultaneously via `@Route([...two paths...])`
 * on the leaf subclass, since the metadata document itself doesn't differ between the two specs for this
 * deployment's purposes.
 *
 * Has no datastore dependency at all (unlike every other `Base*Route` in this library) — it only reads
 * config and the `endpoints` a subclass supplies — so there is deliberately no SQL/Mongo split for this
 * route.
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseOAuthDiscoveryRoute {
    // Automatically injected by ObjectFactory on instantiation. Declared (with the matching `@Init` guard
    // below) even though this route needs nothing further set up, since every route in this library follows
    // this same shape — this is the only one with no `@Inject`/`@Model` of its own, and omitting it was
    // found to trip a route-scanning edge case in `@rapidrest/core`'s `ObjectFactory` for a route class
    // that carries no injected-dependency metadata at all.
    private _objectFactory?: ObjectFactory;

    protected abstract endpoints: OAuthDiscoveryEndpoints;

    @Config("auth:oauth_server:issuer")
    protected issuer?: string;

    @Config("auth:oauth_server:supportedScopes", ["openid", "profile", "email", "phone", "offline_access"])
    protected supportedScopes: string[] = ["openid", "profile", "email", "phone", "offline_access"];

    /**
     * Called on server startup to initialize the route with any defaults. There is nothing to initialize —
     * see the `_objectFactory` field's own doc comment for why this hook still exists.
     */
    @Init
    private async initialize(): Promise<void> {
        if (!this._objectFactory) {
            throw new Error("objectFactory is not set.");
        }
    }

    /**
     * Returns this authorization server's discovery metadata document.
     */
    @Summary("OAuth 2.0 / OIDC discovery metadata")
    @Description(
        "Returns this authorization server's metadata (RFC 8414 / OIDC Discovery §3): its issuer, endpoint " +
            "URLs, and supported capabilities.",
    )
    @Returns([Object])
    @Get()
    public async discovery(@Response res: HttpResponse): Promise<any> {
        res.setHeader("Cache-Control", "public, max-age=3600");

        return {
            issuer: this.issuer,
            authorization_endpoint: this.endpoints.authorization,
            token_endpoint: this.endpoints.token,
            jwks_uri: this.endpoints.jwks,
            ...(this.endpoints.userinfo ? { userinfo_endpoint: this.endpoints.userinfo } : {}),
            ...(this.endpoints.revocation ? { revocation_endpoint: this.endpoints.revocation } : {}),
            ...(this.endpoints.introspection ? { introspection_endpoint: this.endpoints.introspection } : {}),
            ...(this.endpoints.registration ? { registration_endpoint: this.endpoints.registration } : {}),
            scopes_supported: this.supportedScopes,
            response_types_supported: ["code"],
            grant_types_supported: ["authorization_code", "refresh_token", "client_credentials"],
            token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
            subject_types_supported: ["public"],
            id_token_signing_alg_values_supported: ["RS256"],
            code_challenge_methods_supported: ["S256", "plain"],
            claims_supported: [
                "sub",
                "name",
                "given_name",
                "family_name",
                "email",
                "email_verified",
                "phone_number",
                "phone_number_verified",
                "picture",
                "birthdate",
            ],
        };
    }
}
