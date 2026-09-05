///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseOAuthDiscoveryRoute — no HTTP server, no database.
import { BaseOAuthDiscoveryRoute, OAuthDiscoveryEndpoints } from "../../src/routes/BaseOAuthDiscoveryRoute.js";

const FULL_ENDPOINTS: OAuthDiscoveryEndpoints = {
    authorization: "https://auth.example.com/oauth/authorize",
    token: "https://auth.example.com/oauth/token",
    jwks: "https://auth.example.com/oauth/jwks",
    userinfo: "https://auth.example.com/oauth/userinfo",
    revocation: "https://auth.example.com/oauth/revoke",
    introspection: "https://auth.example.com/oauth/introspect",
    registration: "https://auth.example.com/oauth/register",
};

class TestOAuthDiscoveryRoute extends BaseOAuthDiscoveryRoute {
    protected endpoints: OAuthDiscoveryEndpoints;

    constructor(endpoints: OAuthDiscoveryEndpoints) {
        super();
        this.endpoints = endpoints;
    }
}

function makeResponse() {
    return { setHeader: vi.fn() };
}

describe("BaseOAuthDiscoveryRoute Tests", () => {
    describe("initialize", () => {
        it("Throws if objectFactory was not injected.", async () => {
            const route = new TestOAuthDiscoveryRoute(FULL_ENDPOINTS);
            await expect((route as any).initialize()).rejects.toThrow(/objectFactory is not set/);
        });

        it("Succeeds once objectFactory is set.", async () => {
            const route = new TestOAuthDiscoveryRoute(FULL_ENDPOINTS);
            (route as any)._objectFactory = {};
            await expect((route as any).initialize()).resolves.toBeUndefined();
        });
    });

    it("Sets a public, cacheable Cache-Control header.", async () => {
        const route = new TestOAuthDiscoveryRoute(FULL_ENDPOINTS);
        (route as any).issuer = "https://auth.example.com";
        const res = makeResponse();

        await route.discovery(res as any);

        expect(res.setHeader).toHaveBeenCalledWith("Cache-Control", "public, max-age=3600");
    });

    it("Includes every endpoint field and the issuer when all endpoints are configured.", async () => {
        const route = new TestOAuthDiscoveryRoute(FULL_ENDPOINTS);
        (route as any).issuer = "https://auth.example.com";

        const result = await route.discovery(makeResponse() as any);

        expect(result.issuer).toBe("https://auth.example.com");
        expect(result.authorization_endpoint).toBe(FULL_ENDPOINTS.authorization);
        expect(result.token_endpoint).toBe(FULL_ENDPOINTS.token);
        expect(result.jwks_uri).toBe(FULL_ENDPOINTS.jwks);
        expect(result.userinfo_endpoint).toBe(FULL_ENDPOINTS.userinfo);
        expect(result.revocation_endpoint).toBe(FULL_ENDPOINTS.revocation);
        expect(result.introspection_endpoint).toBe(FULL_ENDPOINTS.introspection);
        expect(result.registration_endpoint).toBe(FULL_ENDPOINTS.registration);
    });

    it("Omits userinfo/revocation/introspection/registration fields entirely when not configured.", async () => {
        const route = new TestOAuthDiscoveryRoute({
            authorization: FULL_ENDPOINTS.authorization,
            token: FULL_ENDPOINTS.token,
            jwks: FULL_ENDPOINTS.jwks,
        });
        (route as any).issuer = "https://auth.example.com";

        const result = await route.discovery(makeResponse() as any);

        expect("userinfo_endpoint" in result).toBe(false);
        expect("revocation_endpoint" in result).toBe(false);
        expect("introspection_endpoint" in result).toBe(false);
        expect("registration_endpoint" in result).toBe(false);
    });

    it("Defaults supportedScopes to openid/profile/email/phone/offline_access when unconfigured.", async () => {
        const route = new TestOAuthDiscoveryRoute(FULL_ENDPOINTS);
        (route as any).issuer = "https://auth.example.com";

        const result = await route.discovery(makeResponse() as any);

        expect(result.scopes_supported).toEqual(["openid", "profile", "email", "phone", "offline_access"]);
    });

    it("Reports the grant types, auth methods, and PKCE methods this library actually supports.", async () => {
        const route = new TestOAuthDiscoveryRoute(FULL_ENDPOINTS);
        (route as any).issuer = "https://auth.example.com";

        const result = await route.discovery(makeResponse() as any);

        expect(result.response_types_supported).toEqual(["code"]);
        expect(result.grant_types_supported).toEqual(["authorization_code", "refresh_token", "client_credentials"]);
        expect(result.token_endpoint_auth_methods_supported).toEqual(["client_secret_basic", "client_secret_post", "none"]);
        expect(result.code_challenge_methods_supported).toEqual(["S256", "plain"]);
        expect(result.id_token_signing_alg_values_supported).toEqual(["RS256"]);
        expect(result.subject_types_supported).toEqual(["public"]);
    });
});
