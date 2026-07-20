///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseSecretRoute — no HTTP server, no database. `ModelRoute`'s own `do*`
// behaviors are mocked directly on its prototype (BaseSecretRoute never overrides them, it only calls
// `super.doX(...)`) so we can exercise BaseSecretRoute's own logic (data cleanup, TOTP/WebAuthn
// validation) without booting a full server.
vi.mock("@simplewebauthn/server", () => ({
    generateRegistrationOptions: vi.fn(),
    verifyRegistrationResponse: vi.fn(),
}));

import { ModelRoute } from "@rapidrest/service-core";
import { generateRegistrationOptions, verifyRegistrationResponse } from "@simplewebauthn/server";
import { BaseSecretRoute } from "../../src/routes/BaseSecretRoute.js";
import { SecretType } from "../../src/models/types.js";

const mockGenerateRegistrationOptions = generateRegistrationOptions as unknown as ReturnType<typeof vi.fn>;
const mockVerifyRegistrationResponse = verifyRegistrationResponse as unknown as ReturnType<typeof vi.fn>;

class TestSecretRoute extends BaseSecretRoute<any> {}

function makeReq(session?: any) {
    return { session } as any;
}

describe("BaseSecretRoute Tests", () => {
    afterEach(() => {
        vi.restoreAllMocks();
        mockGenerateRegistrationOptions.mockReset();
        mockVerifyRegistrationResponse.mockReset();
    });

    describe("cleanData", () => {
        it("Removes the data property from a single object.", () => {
            const route = new TestSecretRoute();
            const obj: any = { data: "secret" };

            (route as any).cleanData(obj);

            expect(obj.data).toBeUndefined();
        });

        it("Removes the data property from an array of objects.", () => {
            const route = new TestSecretRoute();
            const objs: any = [{ data: "a" }, { data: "b" }];

            (route as any).cleanData(objs);

            expect(objs[0].data).toBeUndefined();
            expect(objs[1].data).toBeUndefined();
        });
    });

    describe("count", () => {
        it("Delegates to ModelRoute.doCount().", async () => {
            const spy = vi.spyOn(ModelRoute.prototype as any, "doCount").mockResolvedValue("count-result");
            const route = new TestSecretRoute();
            const res: any = {};

            const result = await route.count({ p: 1 }, { q: 1 }, res, { uid: "u1" } as any);

            expect(spy).toHaveBeenCalledWith({ params: { p: 1 }, query: { q: 1 }, res, user: { uid: "u1" } });
            expect(result).toBe("count-result");
        });
    });

    describe("delete", () => {
        it("Delegates to ModelRoute.doDelete(), converting purge='true' to a boolean.", async () => {
            const spy = vi.spyOn(ModelRoute.prototype as any, "doDelete").mockResolvedValue(undefined);
            const route = new TestSecretRoute();
            const req: any = {};

            await route.delete("id-1", "2", "true", req, { uid: "u1" } as any);

            expect(spy).toHaveBeenCalledWith("id-1", { user: { uid: "u1" }, req, version: "2", purge: true });
        });

        it("Converts a non-'true' purge value to false.", async () => {
            const spy = vi.spyOn(ModelRoute.prototype as any, "doDelete").mockResolvedValue(undefined);
            const route = new TestSecretRoute();
            const req: any = {};

            await route.delete("id-1", undefined, undefined, req);

            expect(spy).toHaveBeenCalledWith("id-1", { user: undefined, req, version: undefined, purge: false });
        });
    });

    describe("exists", () => {
        it("Delegates to ModelRoute.doExists().", async () => {
            const spy = vi.spyOn(ModelRoute.prototype as any, "doExists").mockResolvedValue("exists-result");
            const route = new TestSecretRoute();
            const res: any = {};

            const result = await route.exists("id-1", { q: 1 }, res, { uid: "u1" } as any);

            expect(spy).toHaveBeenCalledWith("id-1", { query: { q: 1 }, res, user: { uid: "u1" } });
            expect(result).toBe("exists-result");
        });
    });

    describe("find", () => {
        it("Delegates to ModelRoute.doFind() and cleans data from all results.", async () => {
            const results = [{ data: "a" }, { data: "b" }];
            vi.spyOn(ModelRoute.prototype as any, "doFind").mockResolvedValue(results);
            const route = new TestSecretRoute();

            const result = await route.find({ p: 1 }, { q: 1 }, { uid: "u1" } as any);

            expect(result[0].data).toBeUndefined();
            expect(result[1].data).toBeUndefined();
        });
    });

    describe("findById", () => {
        it("Delegates to ModelRoute.doFindById() and cleans data when a result is found.", async () => {
            vi.spyOn(ModelRoute.prototype as any, "doFindById").mockResolvedValue({ data: "a" });
            const route = new TestSecretRoute();

            const result = await route.findById("id-1", { q: 1 }, { uid: "u1" } as any);

            expect(result?.data).toBeUndefined();
        });

        it("Returns null without attempting to clean data when no result is found.", async () => {
            vi.spyOn(ModelRoute.prototype as any, "doFindById").mockResolvedValue(null);
            const route = new TestSecretRoute();

            const result = await route.findById("unknown", {});

            expect(result).toBeNull();
        });
    });

    describe("truncate", () => {
        it("Delegates to ModelRoute.doTruncate().", async () => {
            const spy = vi.spyOn(ModelRoute.prototype as any, "doTruncate").mockResolvedValue(undefined);
            const route = new TestSecretRoute();

            await route.truncate({ p: 1 }, { q: 1 }, { uid: "u1" } as any);

            expect(spy).toHaveBeenCalledWith({ params: { p: 1 }, query: { q: 1 }, user: { uid: "u1" } });
        });
    });

    describe("create", () => {
        it("Strips data from a single FIDO2/PASSKEY/PASSWORD result.", async () => {
            vi.spyOn(ModelRoute.prototype as any, "doCreate").mockResolvedValue({
                type: SecretType.PASSWORD,
                data: "hash",
            });
            const route = new TestSecretRoute();

            const result: any = await route.create({} as any, {} as any);

            expect(result.data).toBeUndefined();
        });

        it("Strips data from each FIDO2/PASSKEY result in an array.", async () => {
            vi.spyOn(ModelRoute.prototype as any, "doCreate").mockResolvedValue([
                { type: SecretType.FIDO2, data: "a" },
                { type: SecretType.PASSKEY, data: "b" },
            ]);
            const route = new TestSecretRoute();

            const result: any = await route.create([] as any, {} as any);

            expect(result[0].data).toBeUndefined();
            expect(result[1].data).toBeUndefined();
        });

        it("Computes and attaches a provisioning URI for a TOTP result with data.", async () => {
            vi.spyOn(ModelRoute.prototype as any, "doCreate").mockResolvedValue({
                type: SecretType.TOTP,
                userUid: "user-1",
                data: { secret: "JBSWY3DPEHPK3PXP", digits: 6, period: 30, algorithm: "sha1" },
            });
            const route = new TestSecretRoute();

            const result: any = await route.create({} as any, {} as any);

            expect(result.data.uri).toMatch(/^otpauth:\/\/totp\//);
        });

        it("Leaves the result untouched for a TOTP result with no data.", async () => {
            vi.spyOn(ModelRoute.prototype as any, "doCreate").mockResolvedValue({
                type: SecretType.TOTP,
                data: undefined,
            });
            const route = new TestSecretRoute();

            const result: any = await route.create({} as any, {} as any);

            expect(result.data).toBeUndefined();
        });
    });

    describe("validateCreate", () => {
        it("Hashes string data for a PASSWORD secret.", async () => {
            const route = new TestSecretRoute();
            const obj: any = { type: SecretType.PASSWORD, data: "my-password" };

            await (route as any).validateCreate(obj, {} as any);

            expect(obj.data).not.toBe("my-password");
            expect(typeof obj.data).toBe("string");
        });

        it("Throws for a PASSWORD secret with non-string data.", async () => {
            const route = new TestSecretRoute();
            const obj: any = { type: SecretType.PASSWORD, data: { not: "a string" } };

            await expect((route as any).validateCreate(obj, {} as any)).rejects.toThrow(/must specify string data/);
        });

        it("Delegates FIDO2 secrets to validateWebAuthnCreate() with fido2Config.", async () => {
            const route = new TestSecretRoute();
            const spy = vi.spyOn(route as any, "validateWebAuthnCreate").mockResolvedValue(undefined);
            const obj: any = { type: SecretType.FIDO2 };
            const req: any = {};

            await (route as any).validateCreate(obj, req);

            expect(spy).toHaveBeenCalledWith(obj, req, (route as any).fido2Config);
        });

        it("Delegates PASSKEY secrets to validateWebAuthnCreate() with passkeyConfig.", async () => {
            const route = new TestSecretRoute();
            const spy = vi.spyOn(route as any, "validateWebAuthnCreate").mockResolvedValue(undefined);
            const obj: any = { type: SecretType.PASSKEY };
            const req: any = {};

            await (route as any).validateCreate(obj, req);

            expect(spy).toHaveBeenCalledWith(obj, req, (route as any).passkeyConfig);
        });

        it("Delegates TOTP secrets to validateTOTPCreate().", async () => {
            const route = new TestSecretRoute();
            const spy = vi.spyOn(route as any, "validateTOTPCreate").mockResolvedValue(undefined);
            const obj: any = { type: SecretType.TOTP };

            await (route as any).validateCreate(obj, {} as any);

            expect(spy).toHaveBeenCalledWith(obj);
        });

        it("Processes each object in an array of secrets.", async () => {
            const route = new TestSecretRoute();
            const objs: any = [
                { type: SecretType.PASSWORD, data: "pw1" },
                { type: SecretType.PASSWORD, data: "pw2" },
            ];

            await (route as any).validateCreate(objs, {} as any);

            expect(objs[0].data).not.toBe("pw1");
            expect(objs[1].data).not.toBe("pw2");
        });
    });

    describe("validateWebAuthnCreate", () => {
        const config = { rpName: "rapidrest", rpID: "rapidrest", origin: "http://localhost:3000" };

        it("Throws if the request has no session.", async () => {
            const route = new TestSecretRoute();
            const obj: any = {};

            await expect((route as any).validateWebAuthnCreate(obj, makeReq(undefined), config)).rejects.toThrow(
                /requires session support/,
            );
        });

        it("Throws if there is no challenge in progress for the session.", async () => {
            const route = new TestSecretRoute();
            const obj: any = {};

            await expect((route as any).validateWebAuthnCreate(obj, makeReq({}), config)).rejects.toThrow(
                /No WebAuthn registration ceremony in progress/,
            );
        });

        it("Throws if userUid is missing.", async () => {
            const route = new TestSecretRoute();
            const obj: any = { data: {} };

            await expect(
                (route as any).validateWebAuthnCreate(obj, makeReq({ challenge: "c1" }), config),
            ).rejects.toThrow(/must specify a 'userUid'/);
        });

        it("Throws if userUid is an empty string.", async () => {
            const route = new TestSecretRoute();
            const obj: any = { data: {}, userUid: "" };

            await expect(
                (route as any).validateWebAuthnCreate(obj, makeReq({ challenge: "c1" }), config),
            ).rejects.toThrow(/must specify a 'userUid'/);
        });

        it("Clears the session challenge even when the request ultimately fails validation.", async () => {
            const route = new TestSecretRoute();
            const req = makeReq({ challenge: "c1" });
            const obj: any = { data: {}, userUid: "user-1" };

            await expect((route as any).validateWebAuthnCreate(obj, req, config)).rejects.toThrow();

            expect(req.session.challenge).toBeUndefined();
        });

        it("Throws if the submitted data is not a valid WebAuthn registration response.", async () => {
            const route = new TestSecretRoute();
            const obj: any = { data: { not: "valid" }, userUid: "user-1" };

            await expect(
                (route as any).validateWebAuthnCreate(obj, makeReq({ challenge: "c1" }), config),
            ).rejects.toThrow(/must specify a valid WebAuthn registration response/);
        });

        it("Throws if verification does not succeed.", async () => {
            mockVerifyRegistrationResponse.mockResolvedValue({ verified: false });
            const route = new TestSecretRoute();
            const obj: any = {
                data: { id: "cred-1", response: { clientDataJSON: "x", attestationObject: "y" } },
                userUid: "user-1",
            };

            await expect(
                (route as any).validateWebAuthnCreate(obj, makeReq({ challenge: "c1" }), config),
            ).rejects.toThrow(/could not be verified/);
        });

        it("Replaces obj.data with the resulting StoredPasskeyCredential on success.", async () => {
            mockVerifyRegistrationResponse.mockResolvedValue({
                verified: true,
                registrationInfo: {
                    credential: {
                        id: "cred-1",
                        publicKey: new Uint8Array([1, 2, 3]),
                        counter: 0,
                        transports: ["internal"],
                    },
                },
            });
            const route = new TestSecretRoute();
            const obj: any = {
                data: { id: "cred-1", response: { clientDataJSON: "x", attestationObject: "y" } },
                userUid: "user-1",
            };

            await (route as any).validateWebAuthnCreate(obj, makeReq({ challenge: "c1" }), config);

            expect(obj.uid).toBe("cred-1");
            expect(obj.data).toEqual({
                id: "cred-1",
                uid: "user-1",
                publicKey: new Uint8Array([1, 2, 3]),
                counter: 0,
                transports: ["internal"],
            });
        });
    });

    describe("passkeyRegistrationOptions / fido2RegistrationOptions", () => {
        it("Throws 401 when no user is authenticated (passkey).", async () => {
            const route = new TestSecretRoute();
            await expect((route as any).passkeyRegistrationOptions({} as any, undefined)).rejects.toThrow(
                /Authentication is required/,
            );
        });

        it("Throws 401 when no user is authenticated (fido2).", async () => {
            const route = new TestSecretRoute();
            await expect((route as any).fido2RegistrationOptions({} as any, undefined)).rejects.toThrow(
                /Authentication is required/,
            );
        });

        it("Throws if repoUtils is not set when beginning a WebAuthn registration.", async () => {
            const route = new TestSecretRoute();

            await expect(
                (route as any).passkeyRegistrationOptions(makeReq({}), { uid: "user-1" } as any),
            ).rejects.toThrow(/repoUtils is not set/);
        });

        it("Excludes the user's existing credentials of the matching type from the generated options.", async () => {
            mockGenerateRegistrationOptions.mockResolvedValue({ challenge: "c1" });
            const route = new TestSecretRoute();
            const find = vi.fn().mockResolvedValue([{ data: { id: "existing-cred", transports: ["internal"] } }]);
            (route as any).repoUtils = { find };
            const req = makeReq({});

            const result = await (route as any).passkeyRegistrationOptions(req, { uid: "user-1" } as any);

            expect(find).toHaveBeenCalledWith(
                { type: SecretType.PASSKEY, userUid: "user-1" },
                { ignoreACL: true, user: { uid: "user-1" } },
            );
            expect(mockGenerateRegistrationOptions).toHaveBeenCalledWith(
                expect.objectContaining({
                    excludeCredentials: [{ id: "existing-cred", transports: ["internal"] }],
                }),
            );
            expect(result).toEqual({ challenge: "c1" });
            expect(req.session.challenge).toBe("c1");
        });
    });
});
