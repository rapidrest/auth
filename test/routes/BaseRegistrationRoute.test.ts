///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseRegistrationRoute — no HTTP server, no database. otplib is real (it's
// already exercised this way throughout the auth test suites), so `start()`/`verify()` are tested
// against genuine OTP tokens rather than mocked ones.
import { EventUtils } from "@rapidrest/core";
import { RepoUtils } from "@rapidrest/service-core";
import { BaseRegistrationRoute } from "../../src/routes/BaseRegistrationRoute.js";
import { AliasType } from "../../src/models/types.js";
import { generateOTP } from "../../src/auth/shared.js";
import { AuthEventType } from "../../src/auth/events.js";
import { TokenUtils } from "../../src/auth/TokenUtils.js";

function makeRes(): any {
    return { setHeader: vi.fn(), appendHeader: vi.fn() };
}

class FakeAliasClass {
    static readonly name = "FakeAlias";
}
class FakeUserClass {
    static readonly name = "FakeUser";
    // Mirrors `BaseEntity`, whose constructor generates `uid` client-side, before the record is ever
    // persisted — the pre-instantiated user's `uid` is what the alias creation calls key off of.
    uid: string = "new-user-uid";
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
            (route as any)._objectFactory = makeMockObjectFactory(aliasRepo, userRepo);

            await (route as any).initialize();

            expect((route as any).aliasRepo).toBe(aliasRepo);
            expect((route as any).userRepo).toBe(userRepo);
        });

        it("Does not recreate repos if initialize() runs again.", async () => {
            const route = new TestRegistrationRoute();
            (route as any)._objectFactory = makeMockObjectFactory({}, {});
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

        it("Does not throw when sendEmail rejects (failure is logged, not propagated).", async () => {
            const route = new TestRegistrationRoute();
            (route as any).aliasRepo = { find: vi.fn().mockResolvedValue([]) };
            const debug = vi.fn();
            const sendEmail = vi.fn().mockRejectedValue(new Error("provider unavailable"));
            (route as any).messagingUtils = { sendEmail, sendSMS: vi.fn() };
            (route as any).logger = { debug };
            const req = makeReq();

            await expect((route as any).start({ email: "user@example.com" }, req)).resolves.toEqual({});
            // Flush the rejected .catch() microtask registered inside start().
            await new Promise((resolve) => setImmediate(resolve));

            expect(debug).toHaveBeenCalledWith(expect.stringContaining("Failed to send verification e-mail"));
        });

        it("Does not throw when sendSMS rejects (failure is logged, not propagated).", async () => {
            const route = new TestRegistrationRoute();
            (route as any).aliasRepo = { find: vi.fn().mockResolvedValue([]) };
            const debug = vi.fn();
            const sendSMS = vi.fn().mockRejectedValue(new Error("provider unavailable"));
            (route as any).messagingUtils = { sendEmail: vi.fn(), sendSMS };
            (route as any).logger = { debug };
            const req = makeReq();

            await expect((route as any).start({ phone: "+14155552671" }, req)).resolves.toEqual({});
            // Flush the rejected .catch() microtask registered inside start().
            await new Promise((resolve) => setImmediate(resolve));

            expect(debug).toHaveBeenCalledWith(expect.stringContaining("Failed to send verification SMS"));
        });

        it("Rate-limits by the e-mail address before sending an OTP.", async () => {
            const route = new TestRegistrationRoute();
            (route as any).aliasRepo = { find: vi.fn().mockResolvedValue([]) };
            const checkAndIncrement = vi.fn().mockResolvedValue(undefined);
            (route as any).rateLimiter = { checkAndIncrement };
            (route as any).messagingUtils = { sendEmail: vi.fn().mockResolvedValue(undefined), sendSMS: vi.fn() };
            (route as any).logger = { debug: vi.fn() };
            const req = makeReq();

            await (route as any).start({ email: "user@example.com" }, req);

            expect(checkAndIncrement).toHaveBeenCalledWith("user@example.com", req);
        });

        it("Rate-limits by the phone number before sending an OTP.", async () => {
            const route = new TestRegistrationRoute();
            (route as any).aliasRepo = { find: vi.fn().mockResolvedValue([]) };
            const checkAndIncrement = vi.fn().mockResolvedValue(undefined);
            (route as any).rateLimiter = { checkAndIncrement };
            (route as any).messagingUtils = { sendEmail: vi.fn(), sendSMS: vi.fn().mockResolvedValue(undefined) };
            (route as any).logger = { debug: vi.fn() };
            const req = makeReq();

            await (route as any).start({ phone: "+14155552671" }, req);

            expect(checkAndIncrement).toHaveBeenCalledWith("+14155552671", req);
        });

        it("Propagates the rate limiter's error and does not send an OTP once the limit is exceeded.", async () => {
            const route = new TestRegistrationRoute();
            (route as any).aliasRepo = { find: vi.fn().mockResolvedValue([]) };
            const checkAndIncrement = vi.fn().mockRejectedValue(new Error("Too many attempts"));
            (route as any).rateLimiter = { checkAndIncrement };
            const sendEmail = vi.fn();
            (route as any).messagingUtils = { sendEmail, sendSMS: vi.fn() };
            (route as any).logger = { debug: vi.fn() };
            const req = makeReq();

            await expect((route as any).start({ email: "user@example.com" }, req)).rejects.toThrow(
                /Too many attempts/,
            );
            expect(sendEmail).not.toHaveBeenCalled();
        });

        // Regression: rate-limiting used to be skipped entirely on this branch, making an already-registered
        // identifier distinguishable from a non-existing one by request-rate tolerance alone (an attacker
        // could hammer `start()` for a known email forever without ever being throttled, while a guess at a
        // non-existing email would eventually 429). It must now run identically on both branches.
        it("Still rate-limits (but does not send an OTP) when a verified e-mail alias already exists.", async () => {
            const route = new TestRegistrationRoute();
            const find = vi.fn().mockResolvedValue([{ alias: "user@example.com", verified: true }]);
            (route as any).aliasRepo = { find };
            const checkAndIncrement = vi.fn().mockResolvedValue(undefined);
            (route as any).rateLimiter = { checkAndIncrement };
            const sendEmail = vi.fn();
            (route as any).messagingUtils = { sendEmail, sendSMS: vi.fn() };
            const req = makeReq();

            await (route as any).start({ email: "user@example.com" }, req);

            expect(checkAndIncrement).toHaveBeenCalledWith("user@example.com", req);
            expect(sendEmail).not.toHaveBeenCalled();
        });

        it("Still rate-limits (but does not send an OTP) when a verified phone alias already exists.", async () => {
            const route = new TestRegistrationRoute();
            const find = vi.fn().mockResolvedValue([{ alias: "+14155552671", verified: true }]);
            (route as any).aliasRepo = { find };
            const checkAndIncrement = vi.fn().mockResolvedValue(undefined);
            (route as any).rateLimiter = { checkAndIncrement };
            const sendSMS = vi.fn();
            (route as any).messagingUtils = { sendEmail: vi.fn(), sendSMS };
            const req = makeReq();

            await (route as any).start({ phone: "+14155552671" }, req);

            expect(checkAndIncrement).toHaveBeenCalledWith("+14155552671", req);
            expect(sendSMS).not.toHaveBeenCalled();
        });

        // Regression: an exceeded rate limit on the "already registered" branch must surface the same way
        // it does on the "not registered" branch (a thrown error), rather than silently succeeding.
        it("Propagates the rate limiter's error even when a verified alias already exists.", async () => {
            const route = new TestRegistrationRoute();
            const find = vi.fn().mockResolvedValue([{ alias: "user@example.com", verified: true }]);
            (route as any).aliasRepo = { find };
            const checkAndIncrement = vi.fn().mockRejectedValue(new Error("Too many attempts"));
            (route as any).rateLimiter = { checkAndIncrement };
            const req = makeReq();

            await expect((route as any).start({ email: "user@example.com" }, req)).rejects.toThrow(
                /Too many attempts/,
            );
        });

        it("Does not throw when rateLimiter is unset.", async () => {
            const route = new TestRegistrationRoute();
            (route as any).aliasRepo = { find: vi.fn().mockResolvedValue([]) };
            (route as any).messagingUtils = { sendEmail: vi.fn().mockResolvedValue(undefined), sendSMS: vi.fn() };
            (route as any).logger = { debug: vi.fn() };
            const req = makeReq();

            await expect((route as any).start({ email: "user@example.com" }, req)).resolves.toEqual({});
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

        // Regression: verifyOTP() itself has no internal lockout — it's a pure single-use session check —
        // so without a rate limit here an attacker who knows the session's id could brute-force the
        // 6-digit code with unlimited guesses. This mirrors the throttle already applied when the code is
        // first sent (see the "start" tests above).
        it("Rate-limits by the claimed id before verifying the code.", async () => {
            const req = makeReq();
            await generateOTP(req, { id: "user@example.com" });

            const route = new TestRegistrationRoute();
            (route as any).aliasRepo = {};
            (route as any).userRepo = {};
            const checkAndIncrement = vi.fn().mockResolvedValue(undefined);
            (route as any).rateLimiter = { checkAndIncrement };

            await expect(
                (route as any).verify({ email: "user@example.com", token: "000000" }, req),
            ).rejects.toThrow(/verification code is invalid or has expired/);

            expect(checkAndIncrement).toHaveBeenCalledWith("user@example.com", req);
        });

        it("Propagates the rate limiter's error and does not consume the OTP.", async () => {
            const req = makeReq();
            const token = await generateOTP(req, { id: "user@example.com" });

            const route = new TestRegistrationRoute();
            (route as any).aliasRepo = {};
            (route as any).userRepo = {};
            const checkAndIncrement = vi.fn().mockRejectedValue(new Error("Too many attempts"));
            (route as any).rateLimiter = { checkAndIncrement };

            await expect((route as any).verify({ email: "user@example.com", token }, req)).rejects.toThrow(
                /Too many attempts/,
            );

            // The OTP is still valid/unconsumed since verifyOTP() was never reached — a subsequent, properly
            // rate-limited attempt with the same token must still succeed.
            const route2 = new TestRegistrationRoute();
            (route2 as any).aliasRepo = { find: vi.fn().mockResolvedValue([]), create: vi.fn().mockResolvedValue(undefined) };
            (route2 as any).userRepo = { create: vi.fn().mockResolvedValue({ uid: "user-1", roles: [], scopes: [] }) };
            const tokenUtils2 = new TokenUtils();
            (tokenUtils2 as any).jwtConfig = { secret: "test-secret", refresh: { expiresIn: "14 days" } };
            (route2 as any).tokenUtils = tokenUtils2;
            await expect((route2 as any).verify({ email: "user@example.com", token }, req)).resolves.toBeDefined();
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
            const callOrder: string[] = [];
            const aliasCreate = vi.fn().mockImplementation(() => {
                callOrder.push("alias");
                return Promise.resolve(undefined);
            });
            const user = { uid: "new-user-uid", roles: [], scopes: [] };
            const userCreate = vi.fn().mockImplementation(() => {
                callOrder.push("user");
                return Promise.resolve(user);
            });
            (route as any).aliasRepo = { find: vi.fn().mockResolvedValue([]), create: aliasCreate };
            (route as any).userRepo = { create: userCreate };
            const tokenUtils = new TokenUtils();
            (tokenUtils as any).jwtConfig = { secret: "test-secret", refresh: { expiresIn: "14 days" } };
            (route as any).tokenUtils = tokenUtils;
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
            // Regression: the alias is created *before* the user (keyed off the pre-instantiated user's own
            // `uid`, not the not-yet-created record's), so a collision on the alias fails before any `User`
            // row is ever written — see the dedicated orphan-prevention test below.
            expect(aliasCreate).toHaveBeenCalledWith(
                { alias: "user@example.com", type: AliasType.EMAIL, userUid: passedUser.uid, verified: true },
                { ignoreACL: true, user: passedUser },
            );
            expect(callOrder).toEqual(["alias", "user"]);
            // A newly self-registered account is always issued an elevated token (see createAuthResult's
            // `elevated` argument below) so it can immediately set up its own credentials (e.g. MFA) without
            // hitting a `@RequiresElevation`-gated wall it has no way to satisfy yet - hence the extra
            // `elevated` timestamp beyond the plain `user` object.
            expect(result.user).toEqual({ ...user, elevated: expect.any(Number) });
            expect(typeof result.token).toBe("string");
            // Cookie issuance is disabled by default (`auth:cookie.enabled` defaults to `false`).
            expect(res.appendHeader).not.toHaveBeenCalled();
        });

        // Regression: the alias used to be created *after* the user, so a collision on the alias's unique
        // value (e.g. a squatted `name` alias planted ahead of time, per the alias-squatting fix in
        // BaseAliasRoute) would leave an orphaned, unusable `User` row behind — and the victim permanently
        // unable to complete registration with that identifier. Creating the alias first means the failure
        // happens before any `User` row exists at all.
        it("Does not create a User when alias creation fails (no orphaned user row left behind).", async () => {
            const req = makeReq();
            const token = await generateOTP(req, { id: "user@example.com" });

            const route = new TestRegistrationRoute();
            const aliasCreate = vi.fn().mockRejectedValue(new Error("IDENTIFIER_EXISTS"));
            const userCreate = vi.fn();
            (route as any).aliasRepo = { find: vi.fn().mockResolvedValue([]), create: aliasCreate };
            (route as any).userRepo = { create: userCreate };
            const tokenUtils = new TokenUtils();
            (tokenUtils as any).jwtConfig = { secret: "test-secret", refresh: { expiresIn: "14 days" } };
            (route as any).tokenUtils = tokenUtils;

            await expect((route as any).verify({ email: "user@example.com", token }, req)).rejects.toThrow(
                /IDENTIFIER_EXISTS/,
            );

            expect(aliasCreate).toHaveBeenCalledTimes(1);
            expect(userCreate).not.toHaveBeenCalled();
        });

        // Regression: this bypasses `BaseAliasRoute.validateCreate()` (it calls the repo directly), so it must
        // repeat that method's own displacement of stale *unverified* alias claims for the same value here -
        // see the dedicated squatting-displacement integration tests in test/routes/sql and test/routes/mongo.
        it("Deletes a stale unverified e-mail alias claim for the same address before creating the real one.", async () => {
            const req = makeReq();
            const token = await generateOTP(req, { id: "user@example.com" });

            const route = new TestRegistrationRoute();
            const aliasDelete = vi.fn().mockResolvedValue(undefined);
            (route as any).aliasRepo = {
                find: vi.fn().mockResolvedValue([{ uid: "squatter-alias", verified: false }]),
                delete: aliasDelete,
                create: vi.fn().mockResolvedValue(undefined),
            };
            (route as any).userRepo = { create: vi.fn().mockResolvedValue({ uid: "user-1", roles: [], scopes: [] }) };
            const tokenUtils = new TokenUtils();
            (tokenUtils as any).jwtConfig = { secret: "test-secret", refresh: { expiresIn: "14 days" } };
            (route as any).tokenUtils = tokenUtils;

            await (route as any).verify({ email: "user@example.com", token }, req);

            expect(aliasDelete).toHaveBeenCalledWith("squatter-alias", { ignoreACL: true });
        });

        it("Deletes a stale unverified phone alias claim for the same number before creating the real one.", async () => {
            const req = makeReq();
            const token = await generateOTP(req, { id: "+15551234567" });

            const route = new TestRegistrationRoute();
            const aliasDelete = vi.fn().mockResolvedValue(undefined);
            (route as any).aliasRepo = {
                find: vi.fn().mockResolvedValue([{ uid: "squatter-alias", verified: false }]),
                delete: aliasDelete,
                create: vi.fn().mockResolvedValue(undefined),
            };
            (route as any).userRepo = { create: vi.fn().mockResolvedValue({ uid: "user-1", roles: [], scopes: [] }) };
            const tokenUtils = new TokenUtils();
            (tokenUtils as any).jwtConfig = { secret: "test-secret", refresh: { expiresIn: "14 days" } };
            (route as any).tokenUtils = tokenUtils;

            await (route as any).verify({ phone: "+15551234567", token }, req);

            expect(aliasDelete).toHaveBeenCalledWith("squatter-alias", { ignoreACL: true });
        });

        it("Sets a `Set-Cookie` header when cookie issuance is enabled.", async () => {
            const req = makeReq();
            const token = await generateOTP(req, { id: "user@example.com" });

            const route = new TestRegistrationRoute();
            const user = { uid: "user-1", roles: [], scopes: [] };
            (route as any).aliasRepo = { find: vi.fn().mockResolvedValue([]), create: vi.fn().mockResolvedValue(undefined) };
            (route as any).userRepo = { create: vi.fn().mockResolvedValue(user) };
            const tokenUtils = new TokenUtils();
            (tokenUtils as any).jwtConfig = { secret: "test-secret", refresh: { expiresIn: "14 days" } };
            (tokenUtils as any).cookieConfig = {
                enabled: true,
                access: { name: "jwt" },
                refresh: { name: "refresh" },
            };
            (route as any).tokenUtils = tokenUtils;
            const res = makeRes();

            const result = await (route as any).verify({ email: "user@example.com", token }, req, res);

            expect(res.appendHeader).toHaveBeenCalledWith(
                "Set-Cookie",
                expect.stringContaining(`jwt=${result.token}`),
            );
        });

        it("Creates a phone alias when a phone number was verified instead of an e-mail.", async () => {
            const req = makeReq();
            const token = await generateOTP(req, { id: "+15551234567" });

            const route = new TestRegistrationRoute();
            const aliasCreate = vi.fn().mockResolvedValue(undefined);
            const user = { uid: "new-user-uid", roles: [], scopes: [] };
            const userCreate = vi.fn().mockResolvedValue(user);
            (route as any).aliasRepo = { find: vi.fn().mockResolvedValue([]), create: aliasCreate };
            (route as any).userRepo = { create: userCreate };
            const tokenUtils = new TokenUtils();
            (tokenUtils as any).jwtConfig = { secret: "test-secret", refresh: { expiresIn: "14 days" } };
            (route as any).tokenUtils = tokenUtils;

            const result = await (route as any).verify({ phone: "+15551234567", token }, req);

            expect(aliasCreate).toHaveBeenCalledWith(
                { alias: "+15551234567", type: AliasType.PHONE, userUid: "new-user-uid", verified: true },
                { ignoreACL: true, user: expect.any(FakeUserClass) },
            );
            // Self-registration always issues an elevated token - see the same note above.
            expect(result.user).toEqual({ ...user, elevated: expect.any(Number) });
        });

        it("Is single-use: a token cannot be verified twice.", async () => {
            const req = makeReq();
            const token = await generateOTP(req, { id: "user@example.com" });

            const route = new TestRegistrationRoute();
            (route as any).aliasRepo = { find: vi.fn().mockResolvedValue([]), create: vi.fn().mockResolvedValue(undefined) };
            (route as any).userRepo = { create: vi.fn().mockResolvedValue({ uid: "user-1", roles: [], scopes: [] }) };
            const tokenUtils = new TokenUtils();
            (tokenUtils as any).jwtConfig = { secret: "test-secret", refresh: { expiresIn: "14 days" } };
            (route as any).tokenUtils = tokenUtils;

            await (route as any).verify({ email: "user@example.com", token }, req);

            // The challenge was cleared from the session by the first call, so re-submitting the same
            // token fails the session/id match inside verifyOTP() — surfaced the same as any other
            // invalid code.
            await expect((route as any).verify({ email: "user@example.com", token }, req)).rejects.toThrow(
                /verification code is invalid or has expired/,
            );
        });

        it("Records an auth.registration.completed event on success, including the caller's source IP.", async () => {
            const req = makeReq({ socket: { remoteAddress: "1.2.3.4" } });
            const token = await generateOTP(req, { id: "user@example.com" });

            const route = new TestRegistrationRoute();
            const user = { uid: "new-user-uid", roles: [], scopes: [] };
            (route as any).aliasRepo = { find: vi.fn().mockResolvedValue([]), create: vi.fn().mockResolvedValue(undefined) };
            (route as any).userRepo = { create: vi.fn().mockResolvedValue(user) };
            const tokenUtils = new TokenUtils();
            (tokenUtils as any).jwtConfig = { secret: "test-secret", refresh: { expiresIn: "14 days" } };
            (route as any).tokenUtils = tokenUtils;
            const spy = vi.spyOn(EventUtils, "record").mockResolvedValue(undefined);

            await (route as any).verify({ email: "user@example.com", token }, req);

            expect(spy).toHaveBeenCalledWith({
                type: AuthEventType.REGISTRATION_COMPLETED,
                userUid: "new-user-uid",
                ip: "1.2.3.4",
            });
        });

        it("Does not throw when EventUtils.record() itself rejects.", async () => {
            const req = makeReq();
            const token = await generateOTP(req, { id: "user@example.com" });

            const route = new TestRegistrationRoute();
            const user = { uid: "new-user-uid", roles: [], scopes: [] };
            (route as any).aliasRepo = { find: vi.fn().mockResolvedValue([]), create: vi.fn().mockResolvedValue(undefined) };
            (route as any).userRepo = { create: vi.fn().mockResolvedValue(user) };
            const tokenUtils = new TokenUtils();
            (tokenUtils as any).jwtConfig = { secret: "test-secret", refresh: { expiresIn: "14 days" } };
            (route as any).tokenUtils = tokenUtils;
            vi.spyOn(EventUtils, "record").mockRejectedValue(new Error("telemetry down"));

            await expect((route as any).verify({ email: "user@example.com", token }, req)).resolves.toBeDefined();
        });
    });
});
