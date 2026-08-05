///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseRegistrationRoute — no HTTP server, no database. otplib is real (it's
// already exercised this way throughout the auth test suites), so `start()`/`verify()` are tested
// against genuine OTP tokens rather than mocked ones.
import { RepoUtils } from "@rapidrest/service-core";
import { BaseRegistrationRoute } from "../../src/routes/BaseRegistrationRoute.js";
import { AliasType } from "../../src/models/types.js";
import { generateOTP } from "../../src/auth/shared.js";
import { TokenUtils } from "../../src/auth/TokenUtils.js";

function makeRes(): any {
    return { setHeader: vi.fn() };
}

class FakeAliasClass {
    static readonly name = "FakeAlias";
}
class FakeUserClass {
    static readonly name = "FakeUser";
    verified?: boolean;
    constructor(other?: any) {
        if (other) {
            Object.assign(this, other);
        }
    }
}

class TestRegistrationRoute extends BaseRegistrationRoute<any, any> {
    protected aliasClass: any = FakeAliasClass;
    protected userClass: any = FakeUserClass;
}

function makeMockObjectFactory(aliasRepo: any, userRepo: any) {
    const newInstance = vi.fn(async (type: any, opts: any) => {
        if (type === RepoUtils) {
            if (opts.name === FakeAliasClass.name) return aliasRepo;
            if (opts.name === FakeUserClass.name) return userRepo;
            return undefined;
        }
        return undefined;
    });
    return { newInstance };
}

function makeReq(overrides: any = {}): any {
    return {
        method: "POST",
        path: "/",
        url: "/",
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

describe("BaseRegistrationRoute Tests", () => {
    describe("initialize", () => {
        it("Throws if objectFactory is not set.", async () => {
            const route = new TestRegistrationRoute();
            await expect((route as any).initialize()).rejects.toThrow(/objectFactory is not set/);
        });

        it("Creates aliasRepo and userRepo using the object factory.", async () => {
            const aliasRepo = { find: vi.fn() };
            const userRepo = { create: vi.fn() };
            const route = new TestRegistrationRoute();
            (route as any).objectFactory = makeMockObjectFactory(aliasRepo, userRepo);

            await (route as any).initialize();

            expect((route as any).aliasRepo).toBe(aliasRepo);
            expect((route as any).userRepo).toBe(userRepo);
        });

        it("Does not recreate repos if initialize() runs again.", async () => {
            const route = new TestRegistrationRoute();
            (route as any).objectFactory = makeMockObjectFactory({}, {});
            const existingAliasRepo = { find: vi.fn() };
            const existingUserRepo = { create: vi.fn() };
            (route as any).aliasRepo = existingAliasRepo;
            (route as any).userRepo = existingUserRepo;

            await (route as any).initialize();

            expect((route as any).aliasRepo).toBe(existingAliasRepo);
            expect((route as any).userRepo).toBe(existingUserRepo);
        });
    });

    describe("start", () => {
        it("Throws if aliasRepo is not set.", async () => {
            const route = new TestRegistrationRoute();
            const req = makeReq();

            await expect((route as any).start({ email: "user@example.com" }, req)).rejects.toThrow(
                /aliasRepo is not set/,
            );
        });

        it("Throws if the request has no session support.", async () => {
            const route = new TestRegistrationRoute();
            (route as any).aliasRepo = { find: vi.fn() };
            const req = makeReq({ session: undefined });

            await expect((route as any).start({ email: "user@example.com" }, req)).rejects.toThrow(
                /Registration requires session support/,
            );
        });

        it("Rejects when neither a valid e-mail nor phone number is provided.", async () => {
            const route = new TestRegistrationRoute();
            (route as any).aliasRepo = { find: vi.fn() };
            const req = makeReq();

            await expect((route as any).start({ email: "not-an-email" }, req)).rejects.toThrow(
                /valid e-mail address or phone number is required/,
            );
        });

        it("Does not send an OTP and returns silently when a verified e-mail alias already exists.", async () => {
            const route = new TestRegistrationRoute();
            const find = vi.fn().mockResolvedValue([{ alias: "user@example.com", verified: true }]);
            (route as any).aliasRepo = { find };
            const sendEmail = vi.fn();
            (route as any).messagingUtils = { sendEmail, sendSMS: vi.fn() };
            const req = makeReq();

            const result = await (route as any).start({ email: "user@example.com" }, req);

            expect(result).toEqual({});
            expect(find).toHaveBeenCalledWith(
                { alias: "user@example.com", type: AliasType.EMAIL },
                { ignoreACL: true },
            );
            expect(sendEmail).not.toHaveBeenCalled();
        });

        it("Does not send an OTP and returns silently when a verified phone alias already exists.", async () => {
            const route = new TestRegistrationRoute();
            const find = vi.fn().mockResolvedValue([{ alias: "+14155552671", verified: true }]);
            (route as any).aliasRepo = { find };
            const sendSMS = vi.fn();
            (route as any).messagingUtils = { sendEmail: vi.fn(), sendSMS };
            const req = makeReq();

            const result = await (route as any).start({ phone: "+14155552671" }, req);

            expect(result).toEqual({});
            expect(find).toHaveBeenCalledWith(
                { alias: "+14155552671", type: AliasType.PHONE },
                { ignoreACL: true },
            );
            expect(sendSMS).not.toHaveBeenCalled();
        });

        it("Still sends an OTP when a matching alias exists but is unverified (e.g. an abandoned registration).", async () => {
            const route = new TestRegistrationRoute();
            const find = vi.fn().mockResolvedValue([{ alias: "user@example.com", verified: false }]);
            (route as any).aliasRepo = { find };
            const sendEmail = vi.fn().mockResolvedValue(undefined);
            (route as any).messagingUtils = { sendEmail, sendSMS: vi.fn() };
            (route as any).logger = { debug: vi.fn() };
            const req = makeReq();

            await (route as any).start({ email: "user@example.com" }, req);

            expect(sendEmail).toHaveBeenCalledTimes(1);
        });

        it("Sends a one-time code by e-mail (lower-cased and trimmed) and stores challenge data in the session.", async () => {
            const route = new TestRegistrationRoute();
            (route as any).aliasRepo = { find: vi.fn().mockResolvedValue([]) };
            const sendEmail = vi.fn().mockResolvedValue(undefined);
            (route as any).messagingUtils = { sendEmail, sendSMS: vi.fn() };
            (route as any).logger = { debug: vi.fn() };
            const req = makeReq();

            const result = await (route as any).start({ email: "  USER@Example.com  " }, req);

            expect(result).toEqual({});
            expect(sendEmail).toHaveBeenCalledWith(
                "register-otp",
                { totp: expect.any(String) },
                { to: "user@example.com" },
            );
            expect(req.session.id).toBe("user@example.com");
            expect(req.session.secret).toBeDefined();
        });

        it("Sends a one-time code by SMS.", async () => {
            const route = new TestRegistrationRoute();
            (route as any).aliasRepo = { find: vi.fn().mockResolvedValue([]) };
            const sendSMS = vi.fn().mockResolvedValue(undefined);
            (route as any).messagingUtils = { sendEmail: vi.fn(), sendSMS };
            (route as any).logger = { debug: vi.fn() };
            const req = makeReq();

            await (route as any).start({ phone: "+14155552671" }, req);

            expect(sendSMS).toHaveBeenCalledWith(
                "register-otp",
                { totp: expect.any(String) },
                { to: "+14155552671" },
            );
        });

        it("Does not throw when messagingUtils is unset.", async () => {
            const route = new TestRegistrationRoute();
            (route as any).aliasRepo = { find: vi.fn().mockResolvedValue([]) };
            (route as any).logger = { debug: vi.fn() };
            const req = makeReq();

            await expect((route as any).start({ email: "user@example.com" }, req)).resolves.toEqual({});
        });

        it("Returns {} without sending anything when neither e-mail nor phone is provided.", async () => {
            const route = new TestRegistrationRoute();
            const find = vi.fn();
            (route as any).aliasRepo = { find };
            const req = makeReq();

            const result = await (route as any).start({}, req);

            expect(result).toEqual({});
            expect(find).not.toHaveBeenCalled();
        });
    });

    describe("verify", () => {
        it("Throws if aliasRepo is not set.", async () => {
            const route = new TestRegistrationRoute();
            (route as any).userRepo = {};
            const req = makeReq();

            await expect(
                (route as any).verify({ email: "user@example.com", token: "123456" }, req),
            ).rejects.toThrow(/aliasRepo is not set/);
        });

        it("Throws if userRepo is not set.", async () => {
            const route = new TestRegistrationRoute();
            (route as any).aliasRepo = {};
            const req = makeReq();

            await expect(
                (route as any).verify({ email: "user@example.com", token: "123456" }, req),
            ).rejects.toThrow(/userRepo is not set/);
        });

        it("Throws if the request has no session support.", async () => {
            const route = new TestRegistrationRoute();
            (route as any).aliasRepo = {};
            (route as any).userRepo = {};
            const req = makeReq({ session: undefined });

            await expect(
                (route as any).verify({ email: "user@example.com", token: "123456" }, req),
            ).rejects.toThrow(/Registration requires session support/);
        });

        it("Rejects when the e-mail/token is missing from the request.", async () => {
            const route = new TestRegistrationRoute();
            (route as any).aliasRepo = {};
            (route as any).userRepo = {};
            const req = makeReq();

            await expect((route as any).verify({ email: "user@example.com" }, req)).rejects.toThrow(
                /id and verification code are required/,
            );
        });

        it("Rejects an invalid or expired verification code.", async () => {
            const req = makeReq();
            await generateOTP(req, { id: "user@example.com" });

            const route = new TestRegistrationRoute();
            (route as any).aliasRepo = {};
            (route as any).userRepo = {};

            await expect(
                (route as any).verify({ email: "user@example.com", token: "000000" }, req),
            ).rejects.toThrow(/verification code is invalid or has expired/);
        });

        it("Creates a verified user and e-mail alias, and returns a signed JWT on success.", async () => {
            const req = makeReq();
            const token = await generateOTP(req, { id: "user@example.com" });

            const route = new TestRegistrationRoute();
            const aliasCreate = vi.fn().mockResolvedValue(undefined);
            const user = { uid: "user-1", roles: [], scopes: [] };
            const userCreate = vi.fn().mockResolvedValue(user);
            (route as any).aliasRepo = { create: aliasCreate };
            (route as any).userRepo = { create: userCreate };
            (route as any).jwtConfig = { secret: "test-secret" };
            (route as any).tokenUtils = new TokenUtils();
            const res = makeRes();

            const result = await (route as any).verify({ email: "user@example.com", token }, req, res);

            // The new User is instantiated up front (its `uid` is generated client-side by the entity
            // constructor) and passed as both the object to create *and* `options.user`, so `RepoUtils.
            // create()`'s owner-grant logic attributes ownership of the new record to the user themselves —
            // there's no other authenticated actor to attribute it to during self-registration.
            expect(userCreate).toHaveBeenCalledTimes(1);
            const [passedUser, passedOptions] = userCreate.mock.calls[0];
            expect(passedUser).toBeInstanceOf(FakeUserClass);
            expect(passedUser.verified).toBe(true);
            expect(passedOptions).toEqual({ ignoreACL: true, user: passedUser });
            expect(aliasCreate).toHaveBeenCalledWith(
                { alias: "user@example.com", type: AliasType.EMAIL, userUid: "user-1", verified: true },
                { ignoreACL: true, user },
            );
            expect(result.user).toEqual(user);
            expect(typeof result.token).toBe("string");
            // Cookie issuance is disabled by default (`auth:cookie.enabled` defaults to `false`).
            expect(res.setHeader).not.toHaveBeenCalled();
        });

        it("Sets a `Set-Cookie` header when cookie issuance is enabled.", async () => {
            const req = makeReq();
            const token = await generateOTP(req, { id: "user@example.com" });

            const route = new TestRegistrationRoute();
            const user = { uid: "user-1", roles: [], scopes: [] };
            (route as any).aliasRepo = { create: vi.fn().mockResolvedValue(undefined) };
            (route as any).userRepo = { create: vi.fn().mockResolvedValue(user) };
            (route as any).jwtConfig = { secret: "test-secret" };
            const tokenUtils = new TokenUtils();
            (tokenUtils as any).cookieConfig = { enabled: true };
            (route as any).tokenUtils = tokenUtils;
            const res = makeRes();

            const result = await (route as any).verify({ email: "user@example.com", token }, req, res);

            expect(res.setHeader).toHaveBeenCalledWith("Set-Cookie", expect.stringContaining(`jwt=${result.token}`));
        });

        it("Creates a phone alias when a phone number was verified instead of an e-mail.", async () => {
            const req = makeReq();
            const token = await generateOTP(req, { id: "+15551234567" });

            const route = new TestRegistrationRoute();
            const aliasCreate = vi.fn().mockResolvedValue(undefined);
            const user = { uid: "user-1", roles: [], scopes: [] };
            const userCreate = vi.fn().mockResolvedValue(user);
            (route as any).aliasRepo = { create: aliasCreate };
            (route as any).userRepo = { create: userCreate };
            (route as any).jwtConfig = { secret: "test-secret" };
            (route as any).tokenUtils = new TokenUtils();

            const result = await (route as any).verify({ phone: "+15551234567", token }, req);

            expect(aliasCreate).toHaveBeenCalledWith(
                { alias: "+15551234567", type: AliasType.PHONE, userUid: "user-1", verified: true },
                { ignoreACL: true, user },
            );
            expect(result.user).toEqual(user);
        });

        it("Is single-use: a token cannot be verified twice.", async () => {
            const req = makeReq();
            const token = await generateOTP(req, { id: "user@example.com" });

            const route = new TestRegistrationRoute();
            (route as any).aliasRepo = { create: vi.fn().mockResolvedValue(undefined) };
            (route as any).userRepo = { create: vi.fn().mockResolvedValue({ uid: "user-1", roles: [], scopes: [] }) };
            (route as any).jwtConfig = { secret: "test-secret" };
            (route as any).tokenUtils = new TokenUtils();

            await (route as any).verify({ email: "user@example.com", token }, req);

            // The challenge was cleared from the session by the first call, so re-submitting the same
            // token fails the session/id match inside verifyOTP() — surfaced the same as any other
            // invalid code.
            await expect((route as any).verify({ email: "user@example.com", token }, req)).rejects.toThrow(
                /verification code is invalid or has expired/,
            );
        });
    });
});
