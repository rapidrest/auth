///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
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
import { PasswordConfig } from "../../src/auth/types.js";
import { SecretType } from "../../src/models/types.js";

const mockGenerateRegistrationOptions = generateRegistrationOptions as any;
const mockVerifyRegistrationResponse = verifyRegistrationResponse as any;

// Satisfies every default PasswordConfig rule: length >= 8, lowercase, UPPERCASE, a numeral, and a
// special character from the default `special_chars` set.
const VALID_PASSWORD = "Str0ngP@ss";

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
        it("Throws INTERNAL_ERROR when repoUtils is not set.", async () => {
            const route = new TestSecretRoute();

            await expect(route.find({}, {}, { uid: "u1" } as any)).rejects.toThrow(/internal error/i);
        });

        it("Delegates to ModelRoute.doFind() and cleans data from all results (trusted caller).", async () => {
            const results = [{ data: "a" }, { data: "b" }];
            vi.spyOn(ModelRoute.prototype as any, "doFind").mockResolvedValue(results);
            const route = new TestSecretRoute();
            (route as any).repoUtils = {};

            const result = await route.find({ p: 1 }, { q: 1 }, { uid: "admin-1", roles: ["admin"] } as any);

            expect(result[0].data).toBeUndefined();
            expect(result[1].data).toBeUndefined();
        });

        it("Scopes the query to the caller's own userUid, bypasses ACL, and cleans data (non-trusted caller).", async () => {
            const results = [{ data: "a", userUid: "u1" }];
            const find = vi.fn().mockResolvedValue(results);
            const route = new TestSecretRoute();
            (route as any).repoUtils = { find };

            const result = await route.find({ p: 1 }, { q: 1, limit: 10, page: 2 }, { uid: "u1", roles: [] } as any);

            expect(find).toHaveBeenCalledWith(
                { p: 1, q: 1, limit: 10, page: 2, userUid: "u1" },
                { limit: 10, page: 2, ignoreACL: true, user: { uid: "u1", roles: [] } },
            );
            expect(result[0].data).toBeUndefined();
        });

        it("Discards a client-supplied userUid filter for a non-trusted caller, replacing it with their own.", async () => {
            const find = vi.fn().mockResolvedValue([]);
            const route = new TestSecretRoute();
            (route as any).repoUtils = { find };

            await route.find({}, { userUid: "someone-else" }, { uid: "u1", roles: [] } as any);

            expect(find).toHaveBeenCalledWith(
                expect.objectContaining({ userUid: "u1" }),
                expect.anything(),
            );
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

    describe("getPasswordConfig", () => {
        it("Can retrieve password requirements.", async () => {
            const route = new TestSecretRoute();
            const result: any = await route.getPasswordConfig();
            expect(result).toEqual(new PasswordConfig());
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
            const obj: any = { type: SecretType.PASSWORD, data: VALID_PASSWORD };

            await (route as any).validateCreate(obj, {} as any);

            expect(obj.data).not.toBe(VALID_PASSWORD);
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

        it("Throws for a PASSWORD secret shorter than the configured minimum length.", async () => {
            const route = new TestSecretRoute();
            const obj: any = { type: SecretType.PASSWORD, data: "Ab1!" };

            await expect((route as any).validateCreate(obj, {} as any)).rejects.toThrow(
                /minimum length of: 8/,
            );
        });

        it("Defaults obj.userUid to the authenticated caller's uid when unset.", async () => {
            const route = new TestSecretRoute();
            const obj: any = { type: SecretType.PASSWORD, data: VALID_PASSWORD };

            await (route as any).validateCreate(obj, {}, { uid: "user-1" });

            expect(obj.userUid).toBe("user-1");
        });

        it("Allows a caller to explicitly create a secret for their own uid.", async () => {
            const route = new TestSecretRoute();
            const obj: any = { type: SecretType.PASSWORD, data: VALID_PASSWORD, userUid: "user-1" };

            await expect(
                (route as any).validateCreate(obj, {}, { uid: "user-1" }),
            ).resolves.toBeUndefined();
        });

        it("Rejects creating a secret for another user's uid without a trusted role.", async () => {
            const route = new TestSecretRoute();
            const obj: any = { type: SecretType.PASSWORD, data: VALID_PASSWORD, userUid: "victim-uid" };

            await expect(
                (route as any).validateCreate(obj, {}, { uid: "attacker-uid", roles: [] }),
            ).rejects.toThrow(/does not have permission/);
        });

        it("Allows a trusted (admin) caller to create a secret for another user's uid.", async () => {
            const route = new TestSecretRoute();
            const obj: any = { type: SecretType.PASSWORD, data: VALID_PASSWORD, userUid: "victim-uid" };

            await (route as any).validateCreate(obj, {}, { uid: "admin-uid", roles: ["admin"] });

            expect(obj.userUid).toBe("victim-uid");
        });

        it("Does not enforce ownership when there is no authenticated user (unauthenticated create).", async () => {
            const route = new TestSecretRoute();
            const obj: any = { type: SecretType.PASSWORD, data: VALID_PASSWORD, userUid: "someone-else" };

            await (route as any).validateCreate(obj, {}, undefined);

            expect(obj.userUid).toBe("someone-else");
        });
    });

    describe("validatePassword", () => {
        it("Defaults passwordConfig to the PasswordConfig defaults.", () => {
            const route = new TestSecretRoute();

            expect((route as any).passwordConfig).toEqual(new PasswordConfig());
        });

        it("Throws when the password is shorter than min_length.", () => {
            const route = new TestSecretRoute();

            expect(() => (route as any).validatePassword("Ab1!")).toThrow(/minimum length of: 8/);
        });

        it("Throws when the password has no lowercase letter and require_lowercase is set.", () => {
            const route = new TestSecretRoute();

            expect(() => (route as any).validatePassword("STR0NG!PASS")).toThrow(/lowercase letter/);
        });

        it("Throws when the password has no uppercase letter and require_uppercase is set.", () => {
            const route = new TestSecretRoute();

            expect(() => (route as any).validatePassword("str0ng!pass")).toThrow(/uppercase letter/);
        });

        it("Throws when the password has no numeral and require_numeral is set.", () => {
            const route = new TestSecretRoute();

            expect(() => (route as any).validatePassword("Strong!Pass")).toThrow(/at least one number/);
        });

        it("Throws when the password has no special character and require_special is set.", () => {
            const route = new TestSecretRoute();

            expect(() => (route as any).validatePassword("Str0ngPass")).toThrow(/special character/);
        });

        it("Accepts a password that satisfies every default rule.", () => {
            const route = new TestSecretRoute();

            expect(() => (route as any).validatePassword(VALID_PASSWORD)).not.toThrow();
        });

        it("Skips the lowercase check when require_lowercase is disabled.", () => {
            const route = new TestSecretRoute();
            (route as any).passwordConfig = { ...new PasswordConfig(), require_lowercase: false };

            expect(() => (route as any).validatePassword("STR0NG!PASS")).not.toThrow();
        });

        it("Skips the uppercase check when require_uppercase is disabled.", () => {
            const route = new TestSecretRoute();
            (route as any).passwordConfig = { ...new PasswordConfig(), require_uppercase: false };

            expect(() => (route as any).validatePassword("str0ng!pass")).not.toThrow();
        });

        it("Skips the numeral check when require_numeral is disabled.", () => {
            const route = new TestSecretRoute();
            (route as any).passwordConfig = { ...new PasswordConfig(), require_numeral: false };

            expect(() => (route as any).validatePassword("Strong!Pass")).not.toThrow();
        });

        it("Skips the special-character check when require_special is disabled.", () => {
            const route = new TestSecretRoute();
            (route as any).passwordConfig = { ...new PasswordConfig(), require_special: false };

            expect(() => (route as any).validatePassword("Str0ngPass")).not.toThrow();
        });

        it("Honors a configured minimum password length.", () => {
            const route = new TestSecretRoute();
            (route as any).passwordConfig = { ...new PasswordConfig(), min_length: 12 };

            expect(() => (route as any).validatePassword(VALID_PASSWORD)).toThrow(/minimum length of: 12/);
        });

        it("Honors a configured custom special_chars set, using it to rebuild regexSpecialChars.", () => {
            const route = new TestSecretRoute();
            (route as any).passwordConfig = { ...new PasswordConfig(), special_chars: "~" };
            (route as any).init();

            expect(() => (route as any).validatePassword("Str0ngPass~")).not.toThrow();
            expect(() => (route as any).validatePassword(VALID_PASSWORD)).toThrow(/special character/);
        });
    });

    describe("init", () => {
        it("Rebuilds regexSpecialChars from the configured passwordConfig.special_chars.", () => {
            const route = new TestSecretRoute();
            (route as any).passwordConfig = { ...new PasswordConfig(), special_chars: "~" };

            (route as any).init();

            expect((route as any).regexSpecialChars.test("~")).toBe(true);
            expect((route as any).regexSpecialChars.test("!")).toBe(false);
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

    describe("validateTOTPCreate", () => {
        it("Defaults epochTolerance to [1, 1].", () => {
            const route = new TestSecretRoute();

            expect((route as any).totpConfig.epochTolerance).toEqual([1, 1]);
        });

        it("Captures the configured epochTolerance onto the generated TOTPSecret.", async () => {
            const route = new TestSecretRoute();
            const obj: any = { type: SecretType.TOTP };

            await (route as any).validateTOTPCreate(obj);

            expect(obj.data.epochTolerance).toEqual([1, 1]);
        });
    });

    describe("update", () => {
        it("Throws INTERNAL_ERROR when repoUtils is not set.", async () => {
            const route = new TestSecretRoute();

            await expect(
                route.update("id-1", { uid: "id-1" } as any, {} as any, { uid: "u1" } as any),
            ).rejects.toThrow(/internal error/i);
        });

        it("Throws NOT_FOUND when the secret does not exist.", async () => {
            const findOne = vi.fn().mockResolvedValue(undefined);
            const route = new TestSecretRoute();
            (route as any).repoUtils = { findOne };

            await expect(
                route.update("id-1", { uid: "id-1" } as any, {} as any, { uid: "u1" } as any),
            ).rejects.toThrow(/no resource could be found/i);
            expect(findOne).toHaveBeenCalledWith("id-1", { skipCache: true, user: { uid: "u1" } });
        });

        it("Validates against the existing record before delegating to ModelRoute.doUpdate().", async () => {
            const existing = { uid: "id-1", type: SecretType.PASSWORD, userUid: "u1" };
            const findOne = vi.fn().mockResolvedValue(existing);
            const doUpdateSpy = vi
                .spyOn(ModelRoute.prototype as any, "doUpdate")
                .mockResolvedValue({ uid: "id-1", type: SecretType.PASSWORD, userUid: "u1", data: "hash" });
            const route = new TestSecretRoute();
            (route as any).repoUtils = { findOne, validate: vi.fn().mockResolvedValue(undefined) };
            const validateUpdateSpy = vi.spyOn(route as any, "validateUpdate");
            const obj: any = { uid: "id-1", name: "renamed" };

            const result = await route.update("id-1", obj, {} as any, { uid: "u1" } as any);

            expect(validateUpdateSpy).toHaveBeenCalledWith(obj, existing, { uid: "u1" });
            expect(doUpdateSpy).toHaveBeenCalledWith("id-1", obj, { user: { uid: "u1" } });
            // The response is sanitized the same way create() is - a PASSWORD secret never returns `data`.
            expect(result.data).toBeUndefined();
        });

        it("Does not default a missing userUid onto the update payload (no enforceOwnership side effect).", async () => {
            const existing = { uid: "id-1", type: SecretType.PASSWORD, userUid: "someone-else" };
            const findOne = vi.fn().mockResolvedValue(existing);
            vi.spyOn(ModelRoute.prototype as any, "doUpdate").mockResolvedValue(existing);
            const route = new TestSecretRoute();
            (route as any).repoUtils = { findOne, validate: vi.fn().mockResolvedValue(undefined) };
            // A trusted role editing another user's secret without specifying userUid must not be treated
            // as a re-assignment attempt.
            const obj: any = { uid: "id-1", name: "renamed" };

            await route.update("id-1", obj, {} as any, { uid: "admin-1", roles: ["admin"] } as any);

            expect(obj.userUid).toBeUndefined();
        });

        it("Computes a fresh provisioning URI for an updated TOTP secret's response.", async () => {
            const existing = { uid: "id-1", type: SecretType.TOTP, userUid: "u1" };
            const findOne = vi.fn().mockResolvedValue(existing);
            vi.spyOn(ModelRoute.prototype as any, "doUpdate").mockResolvedValue({
                uid: "id-1",
                type: SecretType.TOTP,
                userUid: "u1",
                data: { secret: "JBSWY3DPEHPK3PXP", digits: 6, period: 30, algorithm: "sha1" },
            });
            const route = new TestSecretRoute();
            (route as any).repoUtils = { findOne };
            vi.spyOn(route as any, "validateUpdate").mockResolvedValue(undefined);

            const result: any = await route.update("id-1", { uid: "id-1" } as any, {} as any, {
                uid: "u1",
            } as any);

            expect(result.data.uri).toMatch(/^otpauth:\/\/totp\//);
        });
    });

    describe("validateUpdate", () => {
        it("Runs base validation via this.validate().", async () => {
            const route = new TestSecretRoute();
            const validateSpy = vi.spyOn(route as any, "validate").mockResolvedValue(undefined);
            const existing: any = { uid: "id-1", type: SecretType.PASSWORD, userUid: "u1" };
            const obj: any = { uid: "id-1" };

            await (route as any).validateUpdate(obj, existing, { uid: "u1" });

            expect(validateSpy).toHaveBeenCalledWith(obj, { user: { uid: "u1" } });
        });

        it("Throws when attempting to change the secret's type.", async () => {
            const route = new TestSecretRoute();
            const existing: any = { uid: "id-1", type: SecretType.PASSWORD, userUid: "u1" };
            const obj: any = { uid: "id-1", type: SecretType.TOTP };

            await expect((route as any).validateUpdate(obj, existing, { uid: "u1" })).rejects.toThrow(
                /Cannot modify the `type`/,
            );
        });

        it("Throws when attempting to re-assign the secret to a different owner.", async () => {
            const route = new TestSecretRoute();
            const existing: any = { uid: "id-1", type: SecretType.PASSWORD, userUid: "u1" };
            const obj: any = { uid: "id-1", userUid: "someone-else" };

            await expect((route as any).validateUpdate(obj, existing, { uid: "u1" })).rejects.toThrow(
                /Cannot re-assign secrets/,
            );
        });

        it("Allows re-sending the same userUid the secret already belongs to.", async () => {
            const route = new TestSecretRoute();
            const existing: any = { uid: "id-1", type: SecretType.PASSWORD, userUid: "u1" };
            const obj: any = { uid: "id-1", userUid: "u1", data: VALID_PASSWORD };

            await expect((route as any).validateUpdate(obj, existing, { uid: "u1" })).resolves.toBeUndefined();
        });

        it("Hashes and validates string data for a PASSWORD secret using existing.type, even when obj.type is omitted.", async () => {
            const route = new TestSecretRoute();
            const existing: any = { uid: "id-1", type: SecretType.PASSWORD, userUid: "u1" };
            const obj: any = { uid: "id-1", data: VALID_PASSWORD };

            await (route as any).validateUpdate(obj, existing, { uid: "u1" });

            expect(obj.data).not.toBe(VALID_PASSWORD);
            expect(typeof obj.data).toBe("string");
        });

        it("Rejects a weak password for a PASSWORD secret even when obj.type is omitted.", async () => {
            const route = new TestSecretRoute();
            const existing: any = { uid: "id-1", type: SecretType.PASSWORD, userUid: "u1" };
            const obj: any = { uid: "id-1", data: "weak" };

            await expect((route as any).validateUpdate(obj, existing, { uid: "u1" })).rejects.toThrow(
                /minimum length of: 8/,
            );
        });

        it("Throws for a PASSWORD secret update with non-string data.", async () => {
            const route = new TestSecretRoute();
            const existing: any = { uid: "id-1", type: SecretType.PASSWORD, userUid: "u1" };
            const obj: any = { uid: "id-1", data: { not: "a string" } };

            await expect((route as any).validateUpdate(obj, existing, { uid: "u1" })).rejects.toThrow(
                /must specify string data/,
            );
        });

        it("Rejects modifying a FIDO2 secret's data, even when obj.type is omitted.", async () => {
            const route = new TestSecretRoute();
            const existing: any = { uid: "id-1", type: SecretType.FIDO2, userUid: "u1" };
            const obj: any = { uid: "id-1", data: { tampered: true } };

            await expect((route as any).validateUpdate(obj, existing, { uid: "u1" })).rejects.toThrow(
                /FIDO2 secrets cannot be modified/,
            );
        });

        it("Rejects modifying a Passkey secret's data, even when obj.type is omitted.", async () => {
            const route = new TestSecretRoute();
            const existing: any = { uid: "id-1", type: SecretType.PASSKEY, userUid: "u1" };
            const obj: any = { uid: "id-1", data: { tampered: true } };

            await expect((route as any).validateUpdate(obj, existing, { uid: "u1" })).rejects.toThrow(
                /Passkey secrets cannot be modified/,
            );
        });

        it("Delegates TOTP data updates to validateTOTPCreate(), even when obj.type is omitted.", async () => {
            const route = new TestSecretRoute();
            const spy = vi.spyOn(route as any, "validateTOTPCreate").mockResolvedValue(undefined);
            const existing: any = { uid: "id-1", type: SecretType.TOTP, userUid: "u1" };
            const obj: any = { uid: "id-1", data: "JBSWY3DPEHPK3PXP" };

            await (route as any).validateUpdate(obj, existing, { uid: "u1" });

            expect(spy).toHaveBeenCalledWith(obj);
        });

        it("Skips type-specific data validation entirely when obj has no `data` field.", async () => {
            const route = new TestSecretRoute();
            const existing: any = { uid: "id-1", type: SecretType.FIDO2, userUid: "u1" };
            const obj: any = { uid: "id-1", name: "renamed" };

            await expect((route as any).validateUpdate(obj, existing, { uid: "u1" })).resolves.toBeUndefined();
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
