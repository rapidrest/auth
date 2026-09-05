///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseOAuthJwksRoute — no HTTP server, no database.
import { RepoUtils } from "@rapidrest/service-core";
import { BaseOAuthJwksRoute } from "../../src/routes/BaseOAuthJwksRoute.js";
import { SigningKeyUtils } from "../../src/auth/SigningKeyUtils.js";

class FakeSigningKeyClass {
    static readonly name = "FakeSigningKey";
}

class TestOAuthJwksRoute extends BaseOAuthJwksRoute<any> {
    protected signingKeyClass: any = FakeSigningKeyClass;
}

function makeMockObjectFactory(signingKeyRepo: any, signingKeyUtils: any) {
    const newInstance = vi.fn(async (type: any, opts: any) => {
        if (type === RepoUtils) {
            if (opts.name === FakeSigningKeyClass.name) return signingKeyRepo;
            return undefined;
        }
        if (type === SigningKeyUtils) {
            return signingKeyUtils;
        }
        return undefined;
    });
    return { newInstance };
}

describe("BaseOAuthJwksRoute Tests", () => {
    describe("initialize", () => {
        it("Throws if objectFactory was not injected.", async () => {
            const route = new TestOAuthJwksRoute();

            await expect((route as any).initialize()).rejects.toThrow(/objectFactory is not set/);
        });

        it("Creates signingKeyRepo and signingKeyUtils using the object factory.", async () => {
            const signingKeyRepo = { find: vi.fn() };
            const signingKeyUtils = { getPublicJwks: vi.fn() };
            const route = new TestOAuthJwksRoute();
            (route as any)._objectFactory = makeMockObjectFactory(signingKeyRepo, signingKeyUtils);

            await (route as any).initialize();

            expect((route as any).signingKeyRepo).toBe(signingKeyRepo);
            expect((route as any).signingKeyUtils).toBe(signingKeyUtils);
        });

        it("Does not recreate the repo/utils if initialize() runs again.", async () => {
            const route = new TestOAuthJwksRoute();
            (route as any)._objectFactory = makeMockObjectFactory({}, {});
            const existingRepo = { find: vi.fn() };
            const existingUtils = { getPublicJwks: vi.fn() };
            (route as any).signingKeyRepo = existingRepo;
            (route as any).signingKeyUtils = existingUtils;

            await (route as any).initialize();

            expect((route as any).signingKeyRepo).toBe(existingRepo);
            expect((route as any).signingKeyUtils).toBe(existingUtils);
        });
    });

    describe("jwks", () => {
        it("Returns the public JWK set and sets a Cache-Control header derived from the rotation interval.", async () => {
            const route = new TestOAuthJwksRoute();
            const jwks = { keys: [{ kid: "key-1", kty: "RSA" }] };
            (route as any).signingKeyUtils = {
                getPublicJwks: vi.fn(async () => jwks),
                getJwksCacheMaxAgeSeconds: vi.fn(() => 1234),
            };
            const res = { setHeader: vi.fn() };

            const result = await route.jwks(res as any);

            expect(result).toBe(jwks);
            expect(res.setHeader).toHaveBeenCalledWith("Cache-Control", "public, max-age=1234");
        });

        it("Throws if signingKeyUtils was not initialized.", async () => {
            const route = new TestOAuthJwksRoute();
            const res = { setHeader: vi.fn() };

            await expect(route.jwks(res as any)).rejects.toThrow(/signingKeyUtils is not set/);
        });
    });
});
