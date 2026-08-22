///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for OIDCStrategy — no HTTP server, no database. The provider is a third-party
// HTTP service (mocked via axios) and JWT/JWKS verification is mocked too (that's jsonwebtoken's and
// jwks-rsa's own tested responsibility); these tests verify OIDCStrategy's own orchestration.
vi.mock("axios", () => ({
    default: {
        get: vi.fn(),
        post: vi.fn(),
    },
}));
vi.mock("jsonwebtoken", () => ({
    decode: vi.fn(),
    verify: vi.fn(),
}));
vi.mock("jwks-rsa", () => ({
    default: vi.fn(),
}));

import type { HttpRequest, HttpResponse } from "@rapidrest/service-core";
import axios from "axios";
import * as jwt from "jsonwebtoken";
import jwksClientFactory from "jwks-rsa";
import { OIDCProvider, OIDCStrategy, OIDCStrategyOptions } from "../../src/auth/OIDCStrategy.js";

const mockPost = axios.post as any;
const mockGet = axios.get as any;
const mockJwtDecode = jwt.decode as any;
const mockJwtVerify = jwt.verify as any;
const mockJwksClientFactory = jwksClientFactory as any;

function makeProvider(overrides: Partial<OIDCProvider> = {}): OIDCProvider {
    return {
        name: "test",
        authorizationURL: "https://provider.example.com/authorize",
        clientID: "client-id-1",
        clientSecret: "client-secret-1",
        protocol: "oauth2",
        redirectURI: "https://app.example.com/callback",
        tokenURL: "https://provider.example.com/token",
        ...overrides,
    };
}

function makeReq(overrides: Partial<HttpRequest> = {}): HttpRequest {
    return {
        method: "GET",
        path: "/auth/oidc",
        url: "/auth/oidc",
        headers: {},
        params: {},
        query: {},
        body: undefined,
        cookies: {},
        signedCookies: {},
        session: {},
        socket: {},
        ...overrides,
    };
}

function makeRes(): HttpResponse {
    return {
        statusCode: 200,
        headersSent: false,
        writableEnded: false,
        status: vi.fn().mockReturnThis(),
        setHeader: vi.fn().mockReturnThis(),
        getHeader: vi.fn(),
        json: vi.fn(),
        send: vi.fn(),
        end: vi.fn(),
        onFinish: vi.fn(),
    };
}

describe("OIDCStrategy Tests", () => {
    beforeEach(() => {
        mockPost.mockReset();
        mockGet.mockReset();
        mockJwtDecode.mockReset();
        mockJwtVerify.mockReset();
        mockJwksClientFactory.mockReset();
    });

    describe("constructor", () => {
        it("Uses options.name for the strategy name.", () => {
            const options = new OIDCStrategyOptions("google", makeProvider());
            const strategy = new OIDCStrategy(options);
            expect(strategy.name).toBe("google");
        });

        it("Falls back to the default 'oauth' name when options.name is not set.", () => {
            const options = new OIDCStrategyOptions(undefined as any, makeProvider());
            const strategy = new OIDCStrategy(options);
            expect(strategy.name).toBe("oauth");
        });
    });

    describe("authenticate — redirect phase (no code)", () => {
        it("Throws when the provider reports an error via query, with description.", async () => {
            const options = new OIDCStrategyOptions("test", makeProvider());
            const strategy = new OIDCStrategy(options);
            const req = makeReq({ query: { error: "access_denied", error_description: "User declined" } });

            await expect(strategy.authenticate(req, makeRes())).rejects.toMatchObject({
                status: 401,
                message: expect.stringMatching(/OIDC provider returned an error: access_denied - User declined/),
            });
        });

        it("Throws when the provider reports an error via body, without a description.", async () => {
            const options = new OIDCStrategyOptions("test", makeProvider());
            const strategy = new OIDCStrategy(options);
            const req = makeReq({ query: {}, body: { error: "server_error" } });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(
                "OIDC provider returned an error: server_error",
            );
        });

        it("Redirects to the authorization URL and returns undefined.", async () => {
            const options = new OIDCStrategyOptions("test", makeProvider());
            const strategy = new OIDCStrategy(options);
            const req = makeReq({ session: {} });
            const res = makeRes();

            const result = await strategy.authenticate(req, res);

            expect(result).toBeUndefined();
            expect(res.status).toHaveBeenCalledWith(302);
            expect(res.setHeader).toHaveBeenCalledWith("Location", expect.stringContaining("https://provider.example.com/authorize"));
            expect(res.setHeader).toHaveBeenCalledWith("Content-Length", 0);
            expect(res.end).toHaveBeenCalled();
        });

        it("Throws if req.session is missing.", async () => {
            const options = new OIDCStrategyOptions("test", makeProvider());
            const strategy = new OIDCStrategy(options);
            const req = makeReq({ session: undefined });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/session support/);
        });

        it("Rejects a redirect_uri not in the allowed list.", async () => {
            const options = new OIDCStrategyOptions("test", makeProvider());
            const strategy = new OIDCStrategy(options);
            const req = makeReq({ session: {}, query: { redirect_uri: "https://evil.example.com" } });

            await expect(strategy.authenticate(req, makeRes())).rejects.toMatchObject({
                status: 400,
                message: expect.stringMatching(/not in the list of allowed redirect URIs/),
            });
        });

        it("Accepts a redirect_uri that matches one of multiple allowed values.", async () => {
            const options = new OIDCStrategyOptions(
                "test",
                makeProvider({ redirectURI: ["https://app.example.com/callback", "https://app2.example.com/callback"] }),
            );
            const strategy = new OIDCStrategy(options);
            const req = makeReq({ session: {}, query: { redirect_uri: "https://app2.example.com/callback" } });
            const res = makeRes();

            await strategy.authenticate(req, res);

            expect((req.session as any).redirect_uri).toBe("https://app2.example.com/callback");
        });

        it("Includes the client-supplied state as app-correlation data alongside the CSRF token.", async () => {
            const options = new OIDCStrategyOptions("test", makeProvider());
            const strategy = new OIDCStrategy(options);
            const req = makeReq({ session: {}, query: { state: "client-app-data" } });
            const res = makeRes();

            await strategy.authenticate(req, res);

            const location = (res.setHeader as any).mock.calls.find((c: any[]) => c[0] === "Location")[1] as string;
            const url = new URL(location);
            expect(url.searchParams.get("state")).toBe(`${(req.session as any).state}.client-app-data`);
        });

        it("Includes a nonce for the openid protocol but not for oauth2.", async () => {
            const optionsOpenId = new OIDCStrategyOptions("test", makeProvider({ protocol: "openid" }));
            const strategyOpenId = new OIDCStrategy(optionsOpenId);
            const reqOpenId = makeReq({ session: {} });
            await strategyOpenId.authenticate(reqOpenId, makeRes());
            expect((reqOpenId.session as any).nonce).toBeDefined();

            const optionsOAuth2 = new OIDCStrategyOptions("test", makeProvider({ protocol: "oauth2" }));
            const strategyOAuth2 = new OIDCStrategy(optionsOAuth2);
            const reqOAuth2 = makeReq({ session: {} });
            await strategyOAuth2.authenticate(reqOAuth2, makeRes());
            expect((reqOAuth2.session as any).nonce).toBeUndefined();
        });

        it("Uses the requested scope query param over the provider's configured scope.", async () => {
            const options = new OIDCStrategyOptions("test", makeProvider({ scope: ["profile", "email"] }));
            const strategy = new OIDCStrategy(options);
            const req = makeReq({ session: {}, query: { scope: "openid custom" } });
            const res = makeRes();

            await strategy.authenticate(req, res);

            const location = (res.setHeader as any).mock.calls.find((c: any[]) => c[0] === "Location")[1] as string;
            expect(new URL(location).searchParams.get("scope")).toBe("openid custom");
        });

        it("Falls back to the provider's configured scope when none is requested.", async () => {
            const options = new OIDCStrategyOptions("test", makeProvider({ scope: ["profile", "email"] }));
            const strategy = new OIDCStrategy(options);
            const req = makeReq({ session: {} });
            const res = makeRes();

            await strategy.authenticate(req, res);

            const location = (res.setHeader as any).mock.calls.find((c: any[]) => c[0] === "Location")[1] as string;
            expect(new URL(location).searchParams.get("scope")).toBe("profile email");
        });

        describe("PKCE", () => {
            it("Rejects an invalid code_challenge_method.", async () => {
                const options = new OIDCStrategyOptions("test", makeProvider({ pkce: true }));
                const strategy = new OIDCStrategy(options);
                const req = makeReq({ session: {}, query: { code_challenge_method: "bogus" } });

                await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(
                    /Invalid code_challenge_method 'bogus'/,
                );
            });

            it("Accepts a client-requested method that does not conflict with any provider requirement.", async () => {
                const options = new OIDCStrategyOptions("test", makeProvider({ pkce: true }));
                const strategy = new OIDCStrategy(options);
                const req = makeReq({ session: {}, query: { code_challenge_method: "plain" } });
                const res = makeRes();

                await strategy.authenticate(req, res);

                const location = (res.setHeader as any).mock.calls.find((c: any[]) => c[0] === "Location")[1] as string;
                expect(new URL(location).searchParams.get("code_challenge_method")).toBe("plain");
            });

            it("Rejects a client method that conflicts with a provider-mandated method.", async () => {
                const options = new OIDCStrategyOptions("test", makeProvider({ pkce: "S256" }));
                const strategy = new OIDCStrategy(options);
                const req = makeReq({ session: {}, query: { code_challenge_method: "plain" } });

                await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(
                    /requires PKCE method 'S256', but 'plain' was requested/,
                );
            });

            it("Rejects a code_verifier that does not meet RFC 7636 requirements.", async () => {
                const options = new OIDCStrategyOptions("test", makeProvider({ pkce: true }));
                const strategy = new OIDCStrategy(options);
                const req = makeReq({ session: {}, query: { code_verifier: "too-short" } });

                await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(
                    /does not meet RFC 7636 requirements/,
                );
            });

            it("Uses a client-supplied code_verifier and computes the S256 code_challenge.", async () => {
                const options = new OIDCStrategyOptions("test", makeProvider({ pkce: true }));
                const strategy = new OIDCStrategy(options);
                const verifier = "a".repeat(43);
                const req = makeReq({ session: {}, query: { code_verifier: verifier } });
                const res = makeRes();

                await strategy.authenticate(req, res);

                expect((req.session as any).code_verifier).toBe(verifier);
                expect((req.session as any).code_challenge_method).toBe("S256");
                expect((req.session as any).code_challenge).toBeDefined();
            });

            it("Uses the plain code_challenge (equal to the verifier) for the plain method.", async () => {
                const options = new OIDCStrategyOptions("test", makeProvider({ pkce: "plain" }));
                const strategy = new OIDCStrategy(options);
                const verifier = "b".repeat(43);
                const req = makeReq({ session: {}, query: { code_verifier: verifier } });
                const res = makeRes();

                await strategy.authenticate(req, res);

                expect((req.session as any).code_challenge).toBe(verifier);
            });

            it("Uses an explicit code_challenge query param over computing one.", async () => {
                const options = new OIDCStrategyOptions("test", makeProvider({ pkce: true }));
                const strategy = new OIDCStrategy(options);
                const req = makeReq({
                    session: {},
                    query: { code_verifier: "c".repeat(43), code_challenge: "explicit-challenge" },
                });
                const res = makeRes();

                await strategy.authenticate(req, res);

                expect((req.session as any).code_challenge).toBe("explicit-challenge");
            });

            it("Generates a random verifier when the client does not supply one.", async () => {
                const options = new OIDCStrategyOptions("test", makeProvider({ pkce: true }));
                const strategy = new OIDCStrategy(options);
                const req = makeReq({ session: {} });
                const res = makeRes();

                await strategy.authenticate(req, res);

                expect((req.session as any).code_verifier).toBeDefined();
                expect((req.session as any).code_verifier.length).toBeGreaterThanOrEqual(43);
            });
        });
    });

    describe("authenticate — callback phase (code present)", () => {
        function setupSession(): any {
            return { state: "csrf-token-123" };
        }

        it("Throws if req.session is missing.", async () => {
            const options = new OIDCStrategyOptions("test", makeProvider());
            const strategy = new OIDCStrategy(options);
            const req = makeReq({ query: { code: "auth-code" }, session: undefined });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/session support/);
        });

        it("Throws on a missing/mismatched CSRF state.", async () => {
            const options = new OIDCStrategyOptions("test", makeProvider());
            const strategy = new OIDCStrategy(options);
            const req = makeReq({ query: { code: "auth-code", state: "wrong" }, session: setupSession() });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Invalid or missing state/);
        });

        // Regression/branch guard: a caller that never went through the authorization redirect (so
        // req.session exists, satisfying the earlier "session support" check, but session.state was never
        // set) must not crash when Buffer.from(undefined) would otherwise be attempted.
        it("Throws cleanly when req.session exists but session.state was never set.", async () => {
            const options = new OIDCStrategyOptions("test", makeProvider());
            const strategy = new OIDCStrategy(options);
            const req = makeReq({ query: { code: "auth-code", state: "some-state" }, session: {} });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Invalid or missing state/);
        });

        // Regression: the CSRF state comparison now uses crypto.timingSafeEqual(), which throws on
        // mismatched buffer lengths rather than returning false - a naive fix could leak that as an
        // unhandled 500 instead of the same clean "Invalid or missing state" error. This case is same-
        // length-but-different-content, so it specifically exercises timingSafeEqual() itself rather than
        // the length pre-check short-circuit that the "wrong"/shorter-value case above exercises.
        it("Throws cleanly (not a raw/unhandled error) on a same-length but incorrect CSRF state.", async () => {
            const options = new OIDCStrategyOptions("test", makeProvider());
            const strategy = new OIDCStrategy(options);
            const session = setupSession();
            const wrongSameLength = session.state.slice(0, -1) + (session.state.slice(-1) === "9" ? "8" : "9");
            const req = makeReq({ query: { code: "auth-code", state: wrongSameLength }, session });

            expect(wrongSameLength.length).toBe(session.state.length);
            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Invalid or missing state/);
        });

        it("Throws when no state is supplied at all.", async () => {
            const options = new OIDCStrategyOptions("test", makeProvider());
            const strategy = new OIDCStrategy(options);
            const req = makeReq({ query: { code: "auth-code" }, session: setupSession() });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Invalid or missing state/);
        });

        it("Exchanges the code, retrieves the profile, resolves the user, and clears one-shot session state.", async () => {
            const options = new OIDCStrategyOptions("test", makeProvider({ profileURL: "https://provider.example.com/userinfo" }));
            options.getUser = vi.fn().mockResolvedValue({ uid: "user-1", name: "test", roles: [] });
            const strategy = new OIDCStrategy(options);
            const session = setupSession();
            session.code_verifier = "verifier";
            session.redirect_uri = "https://app.example.com/callback";
            const req = makeReq({
                query: { code: "auth-code", state: `${session.state}.app-data` },
                session,
            });
            mockPost.mockResolvedValue({
                status: 200,
                data: { access_token: "access-token-1", token_type: "Bearer" },
            });
            mockGet.mockResolvedValue({
                status: 200,
                data: { id: "ext-1", username: "tester", email: "test@example.com" },
            });

            const result = await strategy.authenticate(req, makeRes());

            expect(result).toEqual({
                data: { access_token: "access-token-1", token_type: "Bearer" },
                method: "test",
                payload: { access_token: "access-token-1", token_type: "Bearer" },
                state: "app-data",
                user: { uid: "user-1", name: "test", roles: [] },
            });
            expect(session.state).toBeUndefined();
            expect(session.code_verifier).toBeUndefined();
            expect(session.code_challenge).toBeUndefined();
            expect(session.code_challenge_method).toBeUndefined();
            expect(session.nonce).toBeUndefined();
            expect(session.redirect_uri).toBeUndefined();
        });

        it("Accepts the code and state via the request body instead of the query.", async () => {
            const options = new OIDCStrategyOptions("test", makeProvider());
            options.getUser = vi.fn().mockResolvedValue({ uid: "user-1", name: "test", roles: [] });
            const strategy = new OIDCStrategy(options);
            const session = setupSession();
            const req = makeReq({ query: {}, body: { code: "auth-code", state: session.state }, session });
            mockPost.mockResolvedValue({ status: 200, data: { access_token: "tok" } });

            const result = await strategy.authenticate(req, makeRes());

            expect(result?.user).toEqual({ uid: "user-1", name: "test", roles: [] });
        });
    });

    describe("authenticateSync", () => {
        it("Throws 'Not supported' as a 500 (a wiring gap, not an auth failure).", () => {
            const options = new OIDCStrategyOptions("test", makeProvider());
            const strategy = new OIDCStrategy(options);
            expect(() => strategy.authenticateSync(makeReq(), makeRes())).toThrow(
                expect.objectContaining({ status: 500, message: expect.stringMatching(/Not supported/) }),
            );
        });
    });

    describe("exchangeOIDCCode (via authenticate callback phase)", () => {
        const provider = makeProvider();

        async function runExchange(req: HttpRequest): Promise<any> {
            const options = new OIDCStrategyOptions("test", provider);
            options.getUser = vi.fn().mockResolvedValue({ uid: "user-1", name: "test", roles: [] });
            const strategy = new OIDCStrategy(options);
            return strategy.authenticate(req, makeRes());
        }

        it("Throws when the code is missing entirely.", async () => {
            // A falsy code never reaches exchangeOIDCCode() through authenticate() itself — the
            // dispatch check on the same condition takes the redirect branch instead — so this
            // defense-in-depth guard is exercised directly.
            const options = new OIDCStrategyOptions("test", provider);
            const strategy: any = new OIDCStrategy(options);
            const req = makeReq({ query: {}, session: {} });

            await expect(strategy.exchangeOIDCCode(req)).rejects.toThrow(/Authorization code is missing/);
        });

        it("Sends a Basic auth header when the provider has a clientSecret.", async () => {
            mockPost.mockResolvedValue({ status: 200, data: { access_token: "tok" } });
            mockGet.mockResolvedValue(undefined);
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s" } });

            await runExchange(req);

            const headers = mockPost.mock.calls[0][2].headers;
            expect(headers.Authorization).toMatch(/^Basic /);
            expect(mockPost.mock.calls[0][1].client_id).toBeUndefined();
        });

        it("Sends client_id in the body instead of a Basic header when there is no clientSecret.", async () => {
            const options = new OIDCStrategyOptions("test", makeProvider({ clientSecret: "" }));
            options.getUser = vi.fn().mockResolvedValue({ uid: "user-1", name: "test", roles: [] });
            const strategy = new OIDCStrategy(options);
            mockPost.mockResolvedValue({ status: 200, data: { access_token: "tok" } });
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s" } });

            await strategy.authenticate(req, makeRes());

            const headers = mockPost.mock.calls[0][2].headers;
            expect(headers.Authorization).toBeUndefined();
            expect(mockPost.mock.calls[0][1].client_id).toBe("client-id-1");
        });

        it("Includes the PKCE code_verifier from the request body when provided.", async () => {
            const options = new OIDCStrategyOptions("test", makeProvider({ pkce: true }));
            options.getUser = vi.fn().mockResolvedValue({ uid: "user-1", name: "test", roles: [] });
            const strategy = new OIDCStrategy(options);
            mockPost.mockResolvedValue({ status: 200, data: { access_token: "tok" } });
            const req = makeReq({
                query: { state: "s" },
                body: { code: "c", code_verifier: "verifier-from-body" },
                session: { state: "s" },
            });

            await strategy.authenticate(req, makeRes());

            expect(mockPost.mock.calls[0][1].code_verifier).toBe("verifier-from-body");
        });

        it("Throws when the token exchange responds with a non-200 status.", async () => {
            mockPost.mockResolvedValue({ status: 400, data: {} });
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s" } });

            await expect(runExchange(req)).rejects.toThrow(/Failed to retrieve access token/);
        });

        it("Throws when the token exchange responds with no data.", async () => {
            mockPost.mockResolvedValue({ status: 200, data: undefined });
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s" } });

            await expect(runExchange(req)).rejects.toThrow(/Failed to retrieve access token/);
        });

        it("Parses a string response body as JSON.", async () => {
            mockPost.mockResolvedValue({ status: 200, data: JSON.stringify({ access_token: "tok" }) });
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s" } });

            const result = await runExchange(req);

            expect(result?.data).toEqual({ access_token: "tok" });
        });

        it("Propagates the provider's error response body when the request rejects.", async () => {
            const axiosError: any = new Error("Request failed");
            axiosError.response = { data: { error: "invalid_grant" } };
            axiosError.status = 400;
            mockPost.mockRejectedValue(axiosError);
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s" } });

            await expect(runExchange(req)).rejects.toMatchObject({ error: "invalid_grant" });
        });

        it("Wraps a bare network error with a generic message when there is no response body.", async () => {
            mockPost.mockRejectedValue(new Error("network down"));
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s" } });

            await expect(runExchange(req)).rejects.toThrow(/Failed to exchange auth token. network down/);
        });

        it("Wraps a rejection with no .message at all, defaulting to an empty string.", async () => {
            mockPost.mockRejectedValue({});
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s" } });

            await expect(runExchange(req)).rejects.toThrow("Failed to exchange auth token. ");
        });

        it("Resolves the redirect_uri fallback from the first entry of an allowed-list array.", async () => {
            const options = new OIDCStrategyOptions(
                "test",
                makeProvider({ redirectURI: ["https://app.example.com/callback", "https://app2.example.com/callback"] }),
            );
            options.getUser = vi.fn().mockResolvedValue({ uid: "user-1", name: "test", roles: [] });
            const strategy = new OIDCStrategy(options);
            mockPost.mockResolvedValue({ status: 200, data: { access_token: "tok" } });
            // No redirect_uri stashed in the session, so exchangeOIDCCode() falls back to
            // allowedRedirectURIs[0] computed from the array form of provider.redirectURI.
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s" } });

            await strategy.authenticate(req, makeRes());

            expect(mockPost.mock.calls[0][1].redirect_uri).toBe("https://app.example.com/callback");
        });

        it("Falls back to the code_verifier from the query string when the body has none.", async () => {
            const options = new OIDCStrategyOptions("test", makeProvider({ pkce: true }));
            options.getUser = vi.fn().mockResolvedValue({ uid: "user-1", name: "test", roles: [] });
            const strategy = new OIDCStrategy(options);
            mockPost.mockResolvedValue({ status: 200, data: { access_token: "tok" } });
            const req = makeReq({
                query: { code: "c", state: "s", code_verifier: "verifier-from-query" },
                session: { state: "s" },
            });

            await strategy.authenticate(req, makeRes());

            expect(mockPost.mock.calls[0][1].code_verifier).toBe("verifier-from-query");
        });

        it("Falls back to the code_verifier stashed in the session when neither body nor query has one.", async () => {
            const options = new OIDCStrategyOptions("test", makeProvider({ pkce: true }));
            options.getUser = vi.fn().mockResolvedValue({ uid: "user-1", name: "test", roles: [] });
            const strategy = new OIDCStrategy(options);
            mockPost.mockResolvedValue({ status: 200, data: { access_token: "tok" } });
            const req = makeReq({
                query: { code: "c", state: "s" },
                session: { state: "s", code_verifier: "verifier-from-session" },
            });

            await strategy.authenticate(req, makeRes());

            expect(mockPost.mock.calls[0][1].code_verifier).toBe("verifier-from-session");
        });
    });

    describe("retrieveUserProfile (via authenticate callback phase)", () => {
        function makeOpenIdOptions(overrides: Partial<OIDCProvider> = {}): OIDCStrategyOptions {
            const options = new OIDCStrategyOptions(
                "test",
                makeProvider({ protocol: "openid", jwksURI: "https://provider.example.com/jwks", issuer: "https://provider.example.com", ...overrides }),
            );
            options.getUser = vi.fn().mockResolvedValue({ uid: "user-1", name: "test", roles: [] });
            return options;
        }

        it("Returns undefined (and skips getUser's profile arg) when there's no id_token and no profileURL.", async () => {
            const options = new OIDCStrategyOptions("test", makeProvider());
            const getUser = vi.fn().mockResolvedValue({ uid: "user-1", name: "test", roles: [] });
            options.getUser = getUser;
            const strategy = new OIDCStrategy(options);
            mockPost.mockResolvedValue({ status: 200, data: { access_token: "tok" } });
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s" } });

            await strategy.authenticate(req, makeRes());

            expect(getUser.mock.calls[0][1]).toBeUndefined();
        });

        it("Verifies and decodes the id_token for the openid protocol.", async () => {
            const options = makeOpenIdOptions();
            const strategy = new OIDCStrategy(options);
            mockPost.mockResolvedValue({ status: 200, data: { access_token: "tok", id_token: "header.payload.sig" } });
            mockJwtDecode.mockReturnValue({ header: { kid: "key-1" }, payload: {}, signature: "" });
            const getSigningKey = vi.fn().mockResolvedValue({ getPublicKey: () => "public-key" });
            mockJwksClientFactory.mockReturnValue({ getSigningKey });
            mockJwtVerify.mockReturnValue({ nonce: "nonce-123", sub: "ext-1", username: "tester" });
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s", nonce: "nonce-123" } });

            const result = await strategy.authenticate(req, makeRes());

            expect(mockJwtVerify).toHaveBeenCalledWith("header.payload.sig", "public-key", {
                algorithms: ["RS256"],
                issuer: "https://provider.example.com",
                audience: "client-id-1",
            });
            expect(result?.user).toEqual({ uid: "user-1", name: "test", roles: [] });
            // The jwks client is cached across calls for the same URI.
            await strategy.authenticate(
                makeReq({ query: { code: "c2", state: "s2" }, session: { state: "s2", nonce: "nonce-123" } }),
                makeRes(),
            );
            expect(mockJwksClientFactory).toHaveBeenCalledTimes(1);
        });

        it("Throws when jwksURI/issuer are missing for the openid protocol.", async () => {
            const options = new OIDCStrategyOptions("test", makeProvider({ protocol: "openid" }));
            const strategy = new OIDCStrategy(options);
            mockPost.mockResolvedValue({ status: 200, data: { access_token: "tok", id_token: "a.b.c" } });
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s" } });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/missing required/);
        });

        it("Throws when the id_token cannot be decoded.", async () => {
            const options = makeOpenIdOptions();
            const strategy = new OIDCStrategy(options);
            mockPost.mockResolvedValue({ status: 200, data: { access_token: "tok", id_token: "bad-token" } });
            mockJwtDecode.mockReturnValue(null);
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s" } });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/unable to decode JWT header/);
        });

        it("Throws when the id_token's nonce does not match the session.", async () => {
            const options = makeOpenIdOptions();
            const strategy = new OIDCStrategy(options);
            mockPost.mockResolvedValue({ status: 200, data: { access_token: "tok", id_token: "a.b.c" } });
            mockJwtDecode.mockReturnValue({ header: { kid: "key-1" }, payload: {}, signature: "" });
            mockJwksClientFactory.mockReturnValue({ getSigningKey: vi.fn().mockResolvedValue({ getPublicKey: () => "pk" }) });
            mockJwtVerify.mockReturnValue({ nonce: "wrong-nonce" });
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s", nonce: "expected-nonce" } });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Invalid or missing nonce/);
        });

        it("Throws when the session has no nonce to validate against.", async () => {
            const options = makeOpenIdOptions();
            const strategy = new OIDCStrategy(options);
            mockPost.mockResolvedValue({ status: 200, data: { access_token: "tok", id_token: "a.b.c" } });
            mockJwtDecode.mockReturnValue({ header: { kid: "key-1" }, payload: {}, signature: "" });
            mockJwksClientFactory.mockReturnValue({ getSigningKey: vi.fn().mockResolvedValue({ getPublicKey: () => "pk" }) });
            mockJwtVerify.mockReturnValue({ nonce: "some-nonce" });
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s" } });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Invalid or missing nonce/);
        });

        it("Fetches the profile from profileURL when there is no id_token.", async () => {
            const options = new OIDCStrategyOptions(
                "test",
                makeProvider({ profileURL: "https://provider.example.com/userinfo" }),
            );
            options.getUser = vi.fn().mockResolvedValue({ uid: "user-1", name: "test", roles: [] });
            const strategy = new OIDCStrategy(options);
            mockPost.mockResolvedValue({ status: 200, data: { access_token: "tok", token_type: "Bearer" } });
            mockGet.mockResolvedValue({ status: 200, data: { id: "ext-1", username: "tester" } });
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s" } });

            await strategy.authenticate(req, makeRes());

            expect(mockGet).toHaveBeenCalledWith(
                "https://provider.example.com/userinfo",
                expect.objectContaining({ headers: expect.objectContaining({ Authorization: "Bearer tok" }) }),
            );
        });

        it("Parses a string profile response body as JSON.", async () => {
            const options = new OIDCStrategyOptions(
                "test",
                makeProvider({ profileURL: "https://provider.example.com/userinfo" }),
            );
            const getUser = vi.fn().mockResolvedValue({ uid: "user-1", name: "test", roles: [] });
            options.getUser = getUser;
            const strategy = new OIDCStrategy(options);
            mockPost.mockResolvedValue({ status: 200, data: { access_token: "tok" } });
            mockGet.mockResolvedValue({ status: 200, data: JSON.stringify({ id: "ext-1", username: "tester" }) });
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s" } });

            await strategy.authenticate(req, makeRes());

            expect(getUser.mock.calls[0][1]).toMatchObject({ id: "ext-1", name: "tester" });
        });

        it("Throws when the profile request responds with a non-200 status.", async () => {
            const options = new OIDCStrategyOptions(
                "test",
                makeProvider({ profileURL: "https://provider.example.com/userinfo" }),
            );
            options.getUser = vi.fn();
            const strategy = new OIDCStrategy(options);
            mockPost.mockResolvedValue({ status: 200, data: { access_token: "tok" } });
            mockGet.mockResolvedValue({ status: 401, data: {} });
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s" } });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Failed to retrieve user profile/);
        });

        it("Propagates the provider's error response body when the profile request rejects.", async () => {
            const options = new OIDCStrategyOptions(
                "test",
                makeProvider({ profileURL: "https://provider.example.com/userinfo" }),
            );
            options.getUser = vi.fn();
            const strategy = new OIDCStrategy(options);
            mockPost.mockResolvedValue({ status: 200, data: { access_token: "tok" } });
            const axiosError: any = new Error("failed");
            axiosError.response = { data: { error: "invalid_token" } };
            mockGet.mockRejectedValue(axiosError);
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s" } });

            await expect(strategy.authenticate(req, makeRes())).rejects.toMatchObject({ error: "invalid_token" });
        });

        it("Wraps a bare network error from the profile request with a generic message.", async () => {
            const options = new OIDCStrategyOptions(
                "test",
                makeProvider({ profileURL: "https://provider.example.com/userinfo" }),
            );
            options.getUser = vi.fn();
            const strategy = new OIDCStrategy(options);
            mockPost.mockResolvedValue({ status: 200, data: { access_token: "tok" } });
            mockGet.mockRejectedValue(new Error("network down"));
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s" } });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(
                /Failed to retrieve user profile. network down/,
            );
        });

        it("Wraps a profile-request rejection with no .message at all, defaulting to an empty string.", async () => {
            const options = new OIDCStrategyOptions(
                "test",
                makeProvider({ profileURL: "https://provider.example.com/userinfo" }),
            );
            options.getUser = vi.fn();
            const strategy = new OIDCStrategy(options);
            mockPost.mockResolvedValue({ status: 200, data: { access_token: "tok" } });
            mockGet.mockRejectedValue({});
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s" } });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow("Failed to retrieve user profile. ");
        });
    });

    describe("convertProfile mapping", () => {
        it("Supports nested array entries in the profile map.", async () => {
            const options = new OIDCStrategyOptions(
                "test",
                makeProvider({
                    profileURL: "https://provider.example.com/userinfo",
                    profileMap: { tags: ["profile.tag1", "profile.tag2"] },
                }),
            );
            const getUser = vi.fn().mockResolvedValue({ uid: "user-1", name: "test", roles: [] });
            options.getUser = getUser;
            const strategy = new OIDCStrategy(options);
            mockPost.mockResolvedValue({ status: 200, data: { access_token: "tok" } });
            mockGet.mockResolvedValue({ status: 200, data: { id: "ext-1", tag1: "a", tag2: "b" } });
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s" } });

            await strategy.authenticate(req, makeRes());

            expect(getUser.mock.calls[0][1]).toMatchObject({ tags: ["a", "b"] });
        });

        it("Supports nested object entries in the profile map.", async () => {
            const options = new OIDCStrategyOptions(
                "test",
                makeProvider({
                    profileURL: "https://provider.example.com/userinfo",
                    profileMap: { address: { city: "profile.city" } },
                }),
            );
            const getUser = vi.fn().mockResolvedValue({ uid: "user-1", name: "test", roles: [] });
            options.getUser = getUser;
            const strategy = new OIDCStrategy(options);
            mockPost.mockResolvedValue({ status: 200, data: { access_token: "tok" } });
            mockGet.mockResolvedValue({ status: 200, data: { id: "ext-1", city: "Springfield" } });
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s" } });

            await strategy.authenticate(req, makeRes());

            expect(getUser.mock.calls[0][1]).toMatchObject({ address: { city: "Springfield" } });
        });

        it("Throws a descriptive error when a mapped expression fails to evaluate.", async () => {
            const options = new OIDCStrategyOptions(
                "test",
                makeProvider({
                    profileURL: "https://provider.example.com/userinfo",
                    profileMap: { broken: "profile.nested.deeper" },
                }),
            );
            options.getUser = vi.fn();
            const strategy = new OIDCStrategy(options);
            mockPost.mockResolvedValue({ status: 200, data: { access_token: "tok" } });
            mockGet.mockResolvedValue({ status: 200, data: { id: "ext-1" } });
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s" } });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Failed on transforming broken/);
        });
    });

    describe("importOptionalDependency", () => {
        it("Throws a helpful install-hint error when the optional 'jwks-rsa' peer dependency is missing.", async () => {
            vi.doMock("jwks-rsa", () => {
                throw new Error("Cannot find module 'jwks-rsa'");
            });
            vi.resetModules();
            const { OIDCStrategy: FreshOIDCStrategy, OIDCStrategyOptions: FreshOIDCStrategyOptions } = await import(
                "../../src/auth/OIDCStrategy.js"
            );
            const options = new FreshOIDCStrategyOptions(
                "test",
                makeProvider({ protocol: "openid", jwksURI: "https://provider.example.com/jwks", issuer: "https://provider.example.com" }),
            );
            options.getUser = vi.fn();
            const strategy = new FreshOIDCStrategy(options);
            mockPost.mockResolvedValue({ status: 200, data: { access_token: "tok", id_token: "a.b.c" } });
            mockJwtDecode.mockReturnValue({ header: { kid: "key-1" }, payload: {}, signature: "" });
            const req = makeReq({ query: { code: "c", state: "s" }, session: { state: "s" } });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(
                /requires the optional peer dependency 'jwks-rsa'/,
            );

            vi.doUnmock("jwks-rsa");
            vi.resetModules();
        });
    });

    describe("Default OIDCStrategyOptions", () => {
        it("getUser throws if the consumer forgot to override it.", () => {
            const options = new OIDCStrategyOptions("test", makeProvider());
            expect(() => options.getUser("tok", {} as any)).toThrow(/Did you forget to override OIDCStrategyOptions.getUser/);
        });
    });
});
