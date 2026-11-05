///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import config from "../../config.js";
import * as argon2 from "argon2";
import * as crypto from "crypto";
import { agent, request } from "@rapidrest/service-core/test";
import {
    ACLRecord,
    MongoConnection,
    MongoRepository,
    Server,
    ObjectFactory,
    ConnectionManager,
    ACLAction,
    isSqlDataSource,
    RateLimiter,
    RedisSessionStore,
    SessionManager,
} from "@rapidrest/service-core";
import { Logger, MessagingUtils } from "@rapidrest/core";
import * as uuid from "uuid";
import { Repository } from "typeorm";
import { UserSQL } from "../../../src/models/sql/UserSQL.js";
import { MongoMemoryServer } from "mongodb-memory-server";
import { SecretSQL } from "../../../src/models/sql/SecretSQL.js";
import { AliasSQL } from "../../../src/models/sql/AliasSQL.js";
import { ClientSQL } from "../../../src/models/sql/ClientSQL.js";
import { AliasType, ClientType, SecretType, TokenEndpointAuthMethod } from "../../../src/models/types.js";
import { OTPCounters } from "../../../src/auth/OTPCounters.js";
import { normalizePasswordSubmission } from "../../../src/auth/shared.js";
import { PasswordConfig } from "../../../src/auth/types.js";
import { FakeRedisClient } from "../../helpers/FakeRedis.js";

// Stored hashes must be of the canonical (would-be client-hashed) form of a plaintext password, not
// the plaintext itself — see normalizePasswordSubmission() in shared.ts, which
// BaseSecretRoute.processPasswordSecret() applies to every password created/changed through the real
// route. A raw `argon2.hash(password)` here (the pre-client-hashing-support shape) would no longer be
// verifiable via login, since login normalizes a plaintext submission the same way before comparing.
const hashPasswordForLogin = async function (password: string, userUid: string): Promise<string> {
    const canonical = await normalizePasswordSubmission(password, userUid, new PasswordConfig());
    return argon2.hash(canonical);
};

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

// Sent codes must stay valid for their whole TTL, which can never outlive the session they are stored in.
config.set("session:ttl", 1800);
// The generic per-identifier and per-IP limits are raised out of the way so these tests exercise the dedicated
// one-time code limits (`auth:otp:limits`), which are the ones that must hold on their own.
config.set("rateLimit", {
    enabled: true,
    maxAttempts: 100000,
    windowSeconds: 60,
    ip: { maxAttempts: 100000, windowSeconds: 300 },
});

describe("Route:OTPCodesSQL Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-sql", logger, objectFactory });
    const baseUrl = "/sql/auth/elevate";
    const loginUrl = "/sql/auth/password";
    const secretsUrl = "/sql/secrets";
    let userRepo: Repository<UserSQL>;
    let aclRepo: MongoRepository<any>;
    let secretRepo: Repository<SecretSQL>;
    let aliasRepo: Repository<AliasSQL>;
    let clientRepo: Repository<ClientSQL>;
    let messagingUtils: MessagingUtils;

    const createUserSQL = async function (data?: any): Promise<UserSQL> {
        const obj: UserSQL = new UserSQL({
            roles: ["admin"],
            scopes: [],
            verified: true,
            ...data,
        });

        const result: UserSQL = await userRepo.save(obj);

        const records: ACLRecord[] = [
            {
                userOrRoleId: obj.uid,
                actions: [
                    ACLAction.COUNT,
                    ACLAction.CREATE,
                    ACLAction.DELETE,
                    ACLAction.EXISTS,
                    ACLAction.LIST,
                    ACLAction.READ,
                    ACLAction.TRUNCATE,
                    ACLAction.UPDATE,
                ],
            },
        ];

        const acl: any = {
            uid: result.uid,
            dateCreated: new Date(),
            dateModified: new Date(),
            version: 0,
            records,
            parentUid: "UserSQL",
        };
        await aclRepo.save(acl);

        return result;
    };

    const createPasswordSecretSQL = async function (data?: any): Promise<SecretSQL> {
        const userUid: string = data?.userUid ?? uuid.v4();
        const obj: SecretSQL = new SecretSQL({
            data: await hashPasswordForLogin("password", userUid),
            type: SecretType.PASSWORD,
            userUid,
            ...data,
        });

        const result: SecretSQL = await secretRepo.save(obj);

        const records: ACLRecord[] = [
            {
                userOrRoleId: obj.userUid,
                actions: [
                    ACLAction.COUNT,
                    ACLAction.CREATE,
                    ACLAction.DELETE,
                    ACLAction.EXISTS,
                    ACLAction.LIST,
                    ACLAction.READ,
                    ACLAction.TRUNCATE,
                    ACLAction.UPDATE,
                ],
            },
        ];

        const acl: any = {
            uid: result.uid,
            dateCreated: new Date(),
            dateModified: new Date(),
            version: 0,
            records,
            parentUid: "SecretSQL",
        };
        await aclRepo.save(acl);

        return result;
    };

    const createAliasSQL = async function (data?: any): Promise<AliasSQL> {
        const obj: AliasSQL = new AliasSQL({
            alias: uuid.v4(),
            type: AliasType.EMAIL,
            userUid: uuid.v4(),
            verified: true,
            ...data,
        });

        const result: AliasSQL = await aliasRepo.save(obj);

        const records: ACLRecord[] = [
            {
                userOrRoleId: obj.userUid,
                actions: [
                    ACLAction.COUNT,
                    ACLAction.CREATE,
                    ACLAction.DELETE,
                    ACLAction.EXISTS,
                    ACLAction.LIST,
                    ACLAction.READ,
                    ACLAction.TRUNCATE,
                    ACLAction.UPDATE,
                ],
            },
        ];

        const acl: any = {
            uid: result.uid,
            dateCreated: new Date(),
            dateModified: new Date(),
            version: 0,
            records,
            parentUid: "AliasSQL",
        };
        await aclRepo.save(acl);

        return result;
    };

    // Logs in via the normal password flow to obtain a real, non-elevated access token — this route
    // requires the caller to already hold one (see BaseAuthElevationRoute's doc comment: this is a
    // "prove you're still you" check, not a full re-authentication).
    const login = async function (client: any, uid: string): Promise<string> {
        const result = await client
            .get(loginUrl)
            .set("Authorization", `basic ${Buffer.from(uid + ":password").toString("base64")}`);
        return result.body.token;
    };

    beforeAll(async () => {
        await mongod.start();
        await server.start();

        const connMgr: ConnectionManager | undefined = objectFactory.getInstance(ConnectionManager);
        let conn: any = connMgr?.connections.get("acl");
        if (conn instanceof MongoConnection) {
            aclRepo = conn.getMongoRepository("AccessControlListMongo");
        }
        conn = connMgr?.connections.get("sql");
        if (isSqlDataSource(conn)) {
            userRepo = conn.getRepository(UserSQL);
            secretRepo = conn.getRepository(SecretSQL);
            aliasRepo = conn.getRepository(AliasSQL);
            clientRepo = conn.getRepository(ClientSQL);
        } else {
            throw new Error("Could not find sql connection");
        }

        messagingUtils = objectFactory.getInstance(MessagingUtils) as MessagingUtils;
    });

    afterAll(async () => {
        await server.stop();
        await mongod.stop();
        await objectFactory.destroy();
    });

    beforeEach(async () => {
        await userRepo.clear();
        await secretRepo.clear();
        await aliasRepo.clear();
        await clientRepo.clear();

        vi.spyOn(messagingUtils, "sendEmail").mockResolvedValue(undefined as any);
    });

    // ---- One-time code (sent by e-mail/SMS) behavior, end to end -------------------------------------------------
    // The codes are not TOTP: random, case-insensitive, valid until `auth:otp:ttl` (default 10 minutes) or
    // `auth:otp:maxAttempts` wrong guesses (default 5), and single use.

    const otpUrl = "/sql/auth/otp";
    const mfaUrl = "/sql/auth/mfa";
    const registrationUrl = "/sql/registration";
    const aliasesUrl = "/sql/aliases";

    // Only the clock (`Date`) is faked, so the server's real I/O is unaffected while code ages can be simulated.
    let t0 = 0;
    const advance = (ms: number) => vi.setSystemTime(t0 + ms);

    beforeEach(() => {
        t0 = Date.now();
        vi.useFakeTimers({ toFake: ["Date"] });
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    /** The code most recently "sent" by e-mail. */
    const sentCode = (): string => {
        const calls = (messagingUtils.sendEmail as any).mock.calls;
        return calls[calls.length - 1][1].totp;
    };

    /** A code of the same length that differs from `code`. */
    const wrong = (code: string): string => (code[0] === "2" ? "3" : "2") + code.slice(1);

    /** Requests a sign-in code for a new user's e-mail alias, returning everything needed to use it. */
    const requestSignInCode = async function () {
        const user: UserSQL = await createUserSQL();
        const alias: AliasSQL = await createAliasSQL({ userUid: user.uid });
        const client = agent(server.getApplication());
        const challenge = await client.post(otpUrl).send({ id: alias.uid });
        expect(challenge.status).toBeGreaterThanOrEqual(200);
        expect(challenge.status).toBeLessThan(300);
        return { user, alias, client, code: sentCode() };
    };

    it("Sends a 6 character code from the unambiguous alphabet, and accepts it in lower case.", async () => {
        const { alias, client, code } = await requestSignInCode();
        expect(code).toMatch(/^[2-9A-HJKMNP-Z]{6}$/);

        const result = await client.post(otpUrl).send({ id: alias.uid, token: code.toLowerCase() });
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toHaveProperty("token");
    });

    it("Accepts a code copied with a hyphen or surrounding whitespace.", async () => {
        const { alias, client, code } = await requestSignInCode();

        const result = await client.post(otpUrl).send({ id: alias.uid, token: ` ${code.slice(0, 3)}-${code.slice(3)} ` });
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
    });

    it.each([
        ["31 seconds", 31_000],
        ["5 minutes", 5 * 60_000],
        ["just under the 10 minute TTL", 600_000 - 1_000],
    ])("Still accepts a code %s after it was sent.", async (_name, elapsed) => {
        const { alias, client, code } = await requestSignInCode();
        advance(elapsed);

        const result = await client.post(otpUrl).send({ id: alias.uid, token: code });
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
    });

    it("Rejects a code once the TTL has passed, and stays rejected.", async () => {
        const { alias, client, code } = await requestSignInCode();
        advance(600_000 + 1_000);

        expect((await client.post(otpUrl).send({ id: alias.uid, token: code })).status).toBe(401);
        advance(0);
        expect((await client.post(otpUrl).send({ id: alias.uid, token: code })).status).toBe(401);
    });

    it("Lets the user retry after typos, up to the attempt limit.", async () => {
        const { alias, client, code } = await requestSignInCode();

        for (let i = 0; i < 4; i++) {
            expect((await client.post(otpUrl).send({ id: alias.uid, token: wrong(code) })).status).toBe(401);
        }
        const result = await client.post(otpUrl).send({ id: alias.uid, token: code });
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
    });

    it("Invalidates the code after 5 wrong guesses, so even the right code is rejected.", async () => {
        const { alias, client, code } = await requestSignInCode();

        for (let i = 0; i < 5; i++) {
            expect((await client.post(otpUrl).send({ id: alias.uid, token: wrong(code) })).status).toBe(401);
        }
        expect((await client.post(otpUrl).send({ id: alias.uid, token: code })).status).toBe(401);
    });

    it("Is single use: the code cannot sign in a second time.", async () => {
        const { alias, client, code } = await requestSignInCode();

        expect((await client.post(otpUrl).send({ id: alias.uid, token: code })).status).toBeLessThan(300);
        expect((await client.post(otpUrl).send({ id: alias.uid, token: code })).status).toBe(401);
    });

    it("Rejects the code when it is submitted for a different contact, and consumes it.", async () => {
        const { alias, client, code } = await requestSignInCode();
        const other: AliasSQL = await createAliasSQL({ userUid: uuid.v4() });

        expect((await client.post(otpUrl).send({ id: other.uid, token: code })).status).toBe(401);
        expect((await client.post(otpUrl).send({ id: alias.uid, token: code })).status).toBe(401);
    });

    it("Never keeps the plaintext code in the stored session.", async () => {
        const { client, code } = await requestSignInCode();
        const manager: any = objectFactory.getInstance(SessionManager);
        const store: any = manager.store;

        const stored = JSON.stringify([...store.entries.values()].map((e: any) => e.data));
        expect(stored).toContain('"otp"');
        expect(stored).not.toContain(code);
        expect(stored).not.toContain('"token"');
        expect(stored).not.toContain('"secret"');
        expect(client).toBeDefined();
    });

    it("Completes registration with the new code, after a typo, entered in lower case with a space.", async () => {
        const client = agent(server.getApplication());
        const email = `${uuid.v4()}@example.com`;

        expect((await client.post(`${registrationUrl}/start`).send({ email })).status).toBeLessThan(300);
        const code = sentCode();
        expect(code).toMatch(/^[2-9A-HJKMNP-Z]{6}$/);

        expect((await client.post(`${registrationUrl}/verify`).send({ email, token: wrong(code) })).status).toBe(400);
        const spaced = `${code.slice(0, 3)} ${code.slice(3)}`.toLowerCase();
        const result = await client.post(`${registrationUrl}/verify`).send({ email, token: spaced });
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.user.verified).toBe(true);
    });

    it("Rejects a registration code after the TTL.", async () => {
        const client = agent(server.getApplication());
        const email = `${uuid.v4()}@example.com`;

        await client.post(`${registrationUrl}/start`).send({ email });
        const code = sentCode();
        advance(600_000 + 1_000);

        expect((await client.post(`${registrationUrl}/verify`).send({ email, token: code })).status).toBe(400);
    });

    it("Verifies an alias with the new code, after a typo.", async () => {
        const user: UserSQL = await createUserSQL();
        await createPasswordSecretSQL({ userUid: user.uid });
        const alias: AliasSQL = await createAliasSQL({
            userUid: user.uid,
            alias: `${uuid.v4()}@example.com`,
            verified: false,
        });
        const client = agent(server.getApplication());
        const jwt = await login(client, user.uid);

        const sent = await client.get(`${aliasesUrl}/${alias.uid}/sendCode`).set("Authorization", "jwt " + jwt);
        expect(sent.status).toBeLessThan(300);
        const code = sentCode();
        expect(code).toMatch(/^[2-9A-HJKMNP-Z]{6}$/);

        const bad = await client
            .post(`${aliasesUrl}/${alias.uid}/verify`)
            .set("Authorization", "jwt " + jwt)
            .send({ token: wrong(code) });
        expect(bad.status).toBeGreaterThanOrEqual(400);

        advance(5 * 60_000);
        const good = await client
            .post(`${aliasesUrl}/${alias.uid}/verify`)
            .set("Authorization", "jwt " + jwt)
            .send({ token: code.toLowerCase() });
        expect(good.status).toBeGreaterThanOrEqual(200);
        expect(good.status).toBeLessThan(300);
        expect(good.body.verified).toBe(true);
    });

    it("Elevates with the new code, after a typo, entered in lower case.", async () => {
        const user: UserSQL = await createUserSQL();
        await createPasswordSecretSQL({ userUid: user.uid });
        const alias: AliasSQL = await createAliasSQL({ userUid: user.uid });
        const client = agent(server.getApplication());
        const jwt = await login(client, user.uid);

        await client.post(baseUrl).set("Authorization", "jwt " + jwt).send({ methodId: alias.uid });
        const code = sentCode();
        expect(code).toMatch(/^[2-9A-HJKMNP-Z]{6}$/);

        const bad = await client.post(baseUrl).set("Authorization", "jwt " + jwt).send({ token: wrong(code) });
        expect(bad.status).toBe(401);

        const good = await client.post(baseUrl).set("Authorization", "jwt " + jwt).send({ token: code.toLowerCase() });
        expect(good.status).toBeGreaterThanOrEqual(200);
        expect(good.status).toBeLessThan(300);
        expect(good.body.user.elevated).toEqual(expect.any(Number));
    });

    it("Completes the OTP step of MFA with the new code, after a typo.", async () => {
        const user: UserSQL = await createUserSQL();
        await createPasswordSecretSQL({ userUid: user.uid });
        const alias: AliasSQL = await createAliasSQL({ userUid: user.uid });
        const client = agent(server.getApplication());

        const phase1 = await client
            .get(mfaUrl)
            .set("Authorization", `basic ${Buffer.from(user.uid + ":password").toString("base64")}`);
        expect(phase1.status).toBeLessThan(300);
        expect((await client.post(mfaUrl).send({ id: phase1.body.uid, methodId: alias.uid })).status).toBeLessThan(300);
        const code = sentCode();
        expect(code).toMatch(/^[2-9A-HJKMNP-Z]{6}$/);

        expect((await client.post(mfaUrl).send({ id: user.uid, token: wrong(code) })).status).toBe(401);
        const result = await client.post(mfaUrl).send({ id: user.uid, token: code.toLowerCase() });
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.user.uid).toBe(user.uid);
    });



    // ---- Security regressions: cross-flow code reuse, atomic attempt counting, dedicated rate limits ---------------

    const basicAuth = (uid: string) => `basic ${Buffer.from(uid + ":password").toString("base64")}`;

    /** A user with a password and one verified e-mail alias that doubles as its OTP second factor. */
    const createVictim = async function () {
        const user: UserSQL = await createUserSQL();
        await createPasswordSecretSQL({ userUid: user.uid });
        const alias: AliasSQL = await createAliasSQL({ userUid: user.uid, alias: `${uuid.v4()}@example.com` });
        return { user, alias };
    };

    /**
     * Whether a response is the rate limiter's refusal. The framework reports an error thrown by an authentication
     * strategy (the rate limiter's 429 included) as a 401 carrying the error's message, so that is what the sign-in and
     * MFA routes answer; routes that are not authentication strategies answer with the real 429.
     */
    const throttled = (result: any): boolean =>
        [401, 429].includes(result.status) && /too many attempts/i.test(JSON.stringify(result.body ?? ""));

    /** Asserts that a response neither authenticated nor returned any credentials. */
    const expectRefused = (result: any) => {
        expect(result.status).toBeGreaterThanOrEqual(400);
        expect(result.body?.token).toBeUndefined();
        expect(result.body?.user).toBeUndefined();
    };

    describe("MFA one-time code cannot be satisfied by a code from another flow", () => {
        // The exploit this guards: with only the victim's password, a session is given `userUid = victim`. A code
        // issued to the attacker in the same session by another flow used to complete the MFA step as the victim.
        it("Refuses a registration code issued to the attacker, however the id is spelled.", async () => {
            const { user: victim } = await createVictim();
            const attackerEmail = `${uuid.v4()}@example.com`;

            for (const spelling of [attackerEmail, victim.uid]) {
                const attacker = agent(server.getApplication());
                const phase1 = await attacker.get(mfaUrl).set("Authorization", basicAuth(victim.uid));
                expect(phase1.status).toBeLessThan(300);
                expect(phase1.body.methods.length).toBeGreaterThan(0);

                expect((await attacker.post(`${registrationUrl}/start`).send({ email: attackerEmail })).status).toBe(200);
                const code = sentCode();

                expectRefused(await attacker.post(mfaUrl).send({ id: spelling, token: code }));
            }
        });

        it("Refuses a sign-in code issued to the attacker's own alias.", async () => {
            const { user: victim } = await createVictim();
            const attackerUser: UserSQL = await createUserSQL();
            const attackerAlias: AliasSQL = await createAliasSQL({ userUid: attackerUser.uid });

            for (const spelling of [attackerAlias.uid, attackerAlias.alias, victim.uid]) {
                const attacker = agent(server.getApplication());
                expect((await attacker.get(mfaUrl).set("Authorization", basicAuth(victim.uid))).status).toBeLessThan(300);

                expect((await attacker.post(otpUrl).send({ id: attackerAlias.uid })).status).toBeLessThan(300);
                const code = sentCode();

                expectRefused(await attacker.post(mfaUrl).send({ id: spelling, token: code }));
            }
        });

        it("Refuses an elevation code at the MFA step (same id, different purpose).", async () => {
            const { user, alias } = await createVictim();
            const client = agent(server.getApplication());
            const jwt = await login(client, user.uid);

            expect((await client.get(mfaUrl).set("Authorization", basicAuth(user.uid))).status).toBeLessThan(300);
            // An elevation challenge: id is the user's uid, exactly what the MFA step expects, but issued for elevation.
            expect((await client.post(baseUrl).set("Authorization", "jwt " + jwt).send({ methodId: alias.uid })).status)
                .toBeLessThan(300);
            const elevationCode = sentCode();

            expectRefused(await client.post(mfaUrl).send({ id: user.uid, token: elevationCode }));
        });

        it("Refuses an MFA code at elevation (same id, different purpose).", async () => {
            const { user, alias } = await createVictim();
            const client = agent(server.getApplication());
            const jwt = await login(client, user.uid);

            expect((await client.get(mfaUrl).set("Authorization", basicAuth(user.uid))).status).toBeLessThan(300);
            // Begin an elevation (so the session is bound to this user), then replace the pending code by an MFA one.
            expect((await client.post(baseUrl).set("Authorization", "jwt " + jwt).send({ methodId: alias.uid })).status)
                .toBeLessThan(300);
            expect((await client.post(mfaUrl).send({ id: user.uid, methodId: alias.uid })).status).toBeLessThan(300);
            const mfaCode = sentCode();

            const result = await client.post(baseUrl).set("Authorization", "jwt " + jwt).send({ token: mfaCode });
            expect(result.status).toBe(401);
            expect(result.body?.user?.elevated).toBeUndefined();
        });

        it("Refuses a registration code and a sign-in code at alias verification.", async () => {
            const { user } = await createVictim();
            const email = `${uuid.v4()}@example.com`;
            const pending: AliasSQL = await createAliasSQL({ userUid: user.uid, alias: email, verified: false });
            const other: AliasSQL = await createAliasSQL({ userUid: user.uid });
            const client = agent(server.getApplication());
            const jwt = await login(client, user.uid);

            // A registration code for the very same address.
            expect((await client.post(`${registrationUrl}/start`).send({ email })).status).toBe(200);
            const registrationCode = sentCode();
            const viaRegistration = await client
                .post(`${aliasesUrl}/${pending.uid}/verify`)
                .set("Authorization", "jwt " + jwt)
                .send({ token: registrationCode });
            expect(viaRegistration.status).toBe(400);

            // A sign-in code.
            expect((await client.post(otpUrl).send({ id: other.uid })).status).toBeLessThan(300);
            const signInCode = sentCode();
            const viaSignIn = await client
                .post(`${aliasesUrl}/${pending.uid}/verify`)
                .set("Authorization", "jwt " + jwt)
                .send({ token: signInCode });
            expect(viaSignIn.status).toBe(400);

            const stored = await client.get(`${aliasesUrl}/${pending.uid}`).set("Authorization", "jwt " + jwt);
            expect(stored.status).toBeLessThan(300);
            expect(stored.body.verified).toBeFalsy();
        });

        it("Refuses a sign-in code at registration and a registration code at sign-in.", async () => {
            const { alias } = await createVictim();
            const client = agent(server.getApplication());
            const email = `${uuid.v4()}@example.com`;

            expect((await client.post(otpUrl).send({ id: alias.uid })).status).toBeLessThan(300);
            const signInCode = sentCode();
            const register = await client.post(`${registrationUrl}/verify`).send({ email: alias.alias, token: signInCode });
            expect(register.status).toBe(400);
            expect(register.body?.token).toBeUndefined();

            expect((await client.post(`${registrationUrl}/start`).send({ email })).status).toBe(200);
            const registrationCode = sentCode();
            expectRefused(await client.post(otpUrl).send({ id: alias.uid, token: registrationCode }));
            expectRefused(await client.post(otpUrl).send({ id: email, token: registrationCode }));
        });

        it("Drops the phase-1 identity when the MFA verification throws, so a later challenge cannot reuse it.", async () => {
            const { user, alias } = await createVictim();
            const client = agent(server.getApplication());
            expect((await client.get(mfaUrl).set("Authorization", basicAuth(user.uid))).status).toBeLessThan(300);

            // There is no pending code at all, so the verification throws.
            expectRefused(await client.post(mfaUrl).send({ id: user.uid, token: "ABC234" }));

            // The session is no longer bound to the user, so a challenge can't be requested without the password again.
            expectRefused(await client.post(mfaUrl).send({ id: user.uid, methodId: alias.uid }));
        });
    });

    describe("dedicated one-time code rate limits", () => {
        it("Refuses the sixth code requested for one contact within 15 minutes, and recovers afterwards.", async () => {
            const { alias } = await createVictim();
            const client = agent(server.getApplication());
            const sendEmail = messagingUtils.sendEmail as any;
            sendEmail.mockClear();

            for (let i = 0; i < 5; i++) {
                expect((await client.post(otpUrl).send({ id: alias.uid })).status).toBeLessThan(300);
            }
            expect(throttled(await client.post(otpUrl).send({ id: alias.uid }))).toBe(true);
            expect(sendEmail).toHaveBeenCalledTimes(5);

            advance(901_000);
            expect((await client.post(otpUrl).send({ id: alias.uid })).status).toBeLessThan(300);
            expect(sendEmail).toHaveBeenCalledTimes(6);
        });

        it("Refuses an unknown contact the same way, so the limit does not reveal which contacts exist.", async () => {
            const client = agent(server.getApplication());
            const unknown = uuid.v4();
            for (let i = 0; i < 5; i++) {
                expect((await client.post(otpUrl).send({ id: unknown })).status).toBeLessThan(300);
            }
            expect(throttled(await client.post(otpUrl).send({ id: unknown }))).toBe(true);
        });

        it("Refuses a resend flood during registration.", async () => {
            const client = agent(server.getApplication());
            const email = `${uuid.v4()}@example.com`;
            for (let i = 0; i < 5; i++) {
                expect((await client.post(`${registrationUrl}/start`).send({ email })).status).toBe(200);
            }
            expect((await client.post(`${registrationUrl}/start`).send({ email })).status).toBe(429);
        });

        it("Stops an issue-then-guess loop after 20 verification attempts per contact, even with fresh codes.", async () => {
            const { alias } = await createVictim();
            const client = agent(server.getApplication());
            let attempts = 0;
            let blocked = false;

            // Five codes of five guesses each would be 25 guesses; the per-contact limit allows 20.
            outer: for (let code = 0; code < 5; code++) {
                expect((await client.post(otpUrl).send({ id: alias.uid })).status).toBeLessThan(300);
                const real = sentCode();
                for (let guess = 0; guess < 5; guess++) {
                    const result = await client.post(otpUrl).send({ id: alias.uid, token: wrong(real) });
                    if (throttled(result)) {
                        blocked = true;
                        break outer;
                    }
                    expect(result.status).toBe(401);
                    attempts++;
                }
            }

            expect(blocked).toBe(true);
            expect(attempts).toBe(20);
            // Even the correct code is refused now.
            const real = sentCode();
            const result = await client.post(otpUrl).send({ id: alias.uid, token: real });
            expect(throttled(result)).toBe(true);
            expect(result.body?.token).toBeUndefined();
        });

        it("Limits guesses across every alias of one user, not just per alias.", async () => {
            const user: UserSQL = await createUserSQL();
            const aliases: AliasSQL[] = [];
            for (let i = 0; i < 3; i++) {
                aliases.push(await createAliasSQL({ userUid: user.uid, alias: `${uuid.v4()}@example.com` }));
            }
            let attempts = 0;
            let blocked = false;

            // Each alias alone would allow 20 guesses (60 in all); the per-user aggregate allows 50.
            outer: for (const alias of aliases) {
                const client = agent(server.getApplication());
                for (let code = 0; code < 4; code++) {
                    expect((await client.post(otpUrl).send({ id: alias.uid })).status).toBeLessThan(300);
                    const real = sentCode();
                    for (let guess = 0; guess < 5; guess++) {
                        const result = await client.post(otpUrl).send({ id: alias.uid, token: wrong(real) });
                        if (throttled(result)) {
                            blocked = true;
                            break outer;
                        }
                        attempts++;
                    }
                }
            }

            expect(blocked).toBe(true);
            expect(attempts).toBe(50);
        });
    });

    describe("a password alone is not a signed-in session (MFA phase 1 and OAuth authorize)", () => {
        // The exploit this guards: `GET /auth/mfa` with only the victim's password used to set `session.userUid`, the
        // field that means "signed in" everywhere else, so `/oauth/authorize` handed that session an authorization code
        // for the victim, and a public PKCE client exchanges it for the victim's tokens without any second factor.
        const authorizeUrl = "/sql/oauth/authorize";

        const query = (params: Record<string, string>): string =>
            `${authorizeUrl}?${Object.entries(params)
                .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
                .join("&")}`;

        const createOAuthClient = async function (firstParty: boolean): Promise<ClientSQL> {
            return await clientRepo.save(
                new ClientSQL({
                    clientType: ClientType.PUBLIC,
                    clientName: "Mobile App",
                    redirectUris: ["app://callback"],
                    grantTypes: ["authorization_code"],
                    responseTypes: ["code"],
                    scope: "openid profile",
                    tokenEndpointAuthMethod: TokenEndpointAuthMethod.NONE,
                    requirePkce: true,
                    firstParty,
                }),
            );
        };

        const authorize = async (client: any, oauthClient: ClientSQL, extra: Record<string, string> = {}) => {
            const challenge = crypto.createHash("sha256").update(crypto.randomBytes(32).toString("base64url"), "ascii");
            return await client.get(
                query({
                    response_type: "code",
                    client_id: oauthClient.uid,
                    redirect_uri: "app://callback",
                    scope: "openid profile",
                    code_challenge: challenge.digest("base64url"),
                    code_challenge_method: "S256",
                    state: "xyz",
                    ...extra,
                }),
            );
        };

        /** Whether an authorize response handed out an authorization code, in any of the ways it can. */
        const issuedCode = (result: any): boolean =>
            !!result.body?.redirectTo && new URL(result.body.redirectTo).searchParams.has("code");

        /** Runs MFA phase 1 (the password), and nothing else. */
        const phase1 = async (client: any, uid: string) => {
            const result = await client.get(mfaUrl).set("Authorization", basicAuth(uid));
            expect(result.status).toBeLessThan(300);
            expect(result.body.methods.length).toBeGreaterThan(0);
            return result;
        };

        it("Does not authenticate /oauth/authorize after MFA phase 1, for a first-party client.", async () => {
            const { user } = await createVictim();
            const oauthClient = await createOAuthClient(true);
            const attacker = agent(server.getApplication());
            await phase1(attacker, user.uid);

            const result = await authorize(attacker, oauthClient);

            expect(result.body).toEqual({ loginRequired: true });
            expect(issuedCode(result)).toBe(false);
        });

        it("Does not authenticate /oauth/authorize after MFA phase 1 under prompt=none either.", async () => {
            const { user } = await createVictim();
            const oauthClient = await createOAuthClient(true);
            const attacker = agent(server.getApplication());
            await phase1(attacker, user.uid);

            const result = await authorize(attacker, oauthClient, { prompt: "none" });

            expect(issuedCode(result)).toBe(false);
            expect(result.body.redirectTo).toContain("error=login_required");
        });

        it("Does not offer the consent screen after MFA phase 1, for a client that needs consent.", async () => {
            const { user } = await createVictim();
            const oauthClient = await createOAuthClient(false);
            const attacker = agent(server.getApplication());
            await phase1(attacker, user.uid);

            const result = await authorize(attacker, oauthClient);

            expect(result.body).toEqual({ loginRequired: true });
        });

        it("Refuses a consent decision with only MFA phase 1, even holding the victim's own consent ticket.", async () => {
            const { user } = await createVictim();
            await createPasswordSecretSQL({ userUid: user.uid });
            const oauthClient = await createOAuthClient(false);

            // The victim, really signed in, is shown the consent screen.
            const victim = agent(server.getApplication());
            expect((await victim.get(loginUrl).set("Authorization", basicAuth(user.uid))).status).toBeLessThan(300);
            const pending = await authorize(victim, oauthClient);
            expect(pending.body.consentRequired).toBe(true);

            // An attacker with an account of their own (so the request is authenticated and passes CSRF) also knows the
            // victim's password, and runs MFA phase 1 for the victim in the same session.
            const attackerUser: UserSQL = await createUserSQL();
            await createPasswordSecretSQL({ userUid: attackerUser.uid });
            const attacker = agent(server.getApplication());
            expect((await attacker.get(loginUrl).set("Authorization", basicAuth(attackerUser.uid))).status)
                .toBeLessThan(300);
            await phase1(attacker, user.uid);

            // They then submit the victim's consent decision. The session is still the attacker's, so the ticket,
            // which belongs to the victim, is refused and no code is issued.
            const decision = await attacker
                .post(`${authorizeUrl}/consent`)
                .send({ requestId: pending.body.requestId, approved: true });

            expect(decision.status).toBe(403);
            expect(decision.body?.redirectTo).toBeUndefined();

            // The attacker's session is the attacker's own for /authorize too.
            const own = await authorize(attacker, oauthClient);
            expect(own.body.consentRequired).toBe(true);
        });

        it("Refuses a consent decision from a session that has only passed MFA phase 1, with no login of its own.", async () => {
            // The discriminating version of the test above. That one logs the attacker in first, and service-core's
            // `JWTStrategy` then overwrites `session.userUid` with the attacker's own uid from the `jwt` cookie on every
            // authenticated request, which would hide a phase 1 that wrote the victim's uid there. This attacker has no
            // login at all: the only thing in the session that could identify anyone is what phase 1 leaves behind.
            const { user } = await createVictim();
            const oauthClient = await createOAuthClient(false);

            const victim = agent(server.getApplication());
            expect((await victim.get(loginUrl).set("Authorization", basicAuth(user.uid))).status).toBeLessThan(300);
            const pending = await authorize(victim, oauthClient);
            expect(pending.body.consentRequired).toBe(true);

            const attacker = agent(server.getApplication());
            // Any authenticated GET hands out the CSRF cookie (the 401 is expected), which the agent echoes back.
            await attacker.get(aliasesUrl);
            await phase1(attacker, user.uid);

            const decision = await attacker
                .post(`${authorizeUrl}/consent`)
                .send({ requestId: pending.body.requestId, approved: true });

            expect(decision.status).toBe(401);
            expect(decision.body?.redirectTo).toBeUndefined();
        });

        it("Authenticates /oauth/authorize once the second factor is completed.", async () => {
            const { user, alias } = await createVictim();
            const oauthClient = await createOAuthClient(true);
            const client = agent(server.getApplication());
            await phase1(client, user.uid);
            expect((await client.post(mfaUrl).send({ id: user.uid, methodId: alias.uid })).status).toBeLessThan(300);
            const code = sentCode();

            const done = await client.post(mfaUrl).send({ id: user.uid, token: code });
            expect(done.status).toBeLessThan(300);

            expect(issuedCode(await authorize(client, oauthClient))).toBe(true);
        });

        it("Does not sign out a real session when a second factor attempt fails.", async () => {
            const { user, alias } = await createVictim();
            const oauthClient = await createOAuthClient(true);
            const client = agent(server.getApplication());
            // A genuine sign-in (the password route has no second factor).
            expect((await client.get(loginUrl).set("Authorization", basicAuth(user.uid))).status).toBeLessThan(300);
            expect(issuedCode(await authorize(client, oauthClient))).toBe(true);

            // The same session then fails an MFA attempt, with a wrong code and then with no pending code.
            await phase1(client, user.uid);
            expect((await client.post(mfaUrl).send({ id: user.uid, methodId: alias.uid })).status).toBeLessThan(300);
            expectRefused(await client.post(mfaUrl).send({ id: user.uid, token: wrong(sentCode()) }));
            expectRefused(await client.post(mfaUrl).send({ id: user.uid, token: "ABC234" }));

            // Still signed in.
            expect(issuedCode(await authorize(client, oauthClient))).toBe(true);
        });
    });

    describe("one flow cannot spend another flow's counters", () => {
        it("Lets a lockout attempt through /auth/otp naming a victim's uid leave MFA and elevation alone.", async () => {
            const { user, alias } = await createVictim();
            const attacker = agent(server.getApplication());

            // Unauthenticated: use up the sign-in issue budget for the victim's uid, then guess against it.
            let refused = 0;
            for (let i = 0; i < 12; i++) {
                if (throttled(await attacker.post(otpUrl).send({ id: user.uid }))) {
                    refused++;
                }
            }
            expect(refused).toBeGreaterThan(0);
            for (let i = 0; i < 30; i++) {
                const guess = await attacker.post(otpUrl).send({ id: user.uid, token: "ABC234" });
                expect(guess.status).toBe(401);
                expect(throttled(guess)).toBe(false);
            }

            // The victim's second factor still works ...
            const victim = agent(server.getApplication());
            expect((await victim.get(mfaUrl).set("Authorization", basicAuth(user.uid))).status).toBeLessThan(300);
            expect((await victim.post(mfaUrl).send({ id: user.uid, methodId: alias.uid })).status).toBeLessThan(300);
            const mfa = await victim.post(mfaUrl).send({ id: user.uid, token: sentCode() });
            expect(mfa.status).toBeLessThan(300);
            expect(mfa.body.user.uid).toBe(user.uid);

            // ... and so does elevation.
            const jwt = await login(victim, user.uid);
            expect((await victim.post(baseUrl).set("Authorization", "jwt " + jwt).send({ methodId: alias.uid })).status)
                .toBeLessThan(300);
            const elevated = await victim.post(baseUrl).set("Authorization", "jwt " + jwt).send({ token: sentCode() });
            expect(elevated.status).toBeLessThan(300);
            expect(elevated.body.user.elevated).toEqual(expect.any(Number));
        });

        it("Does not let a crafted login id reach the one-time code or elevation counters.", async () => {
            const { user } = await createVictim();
            const limiterStore: any = objectFactory.getInstance<any>(RateLimiter).memoryStore;
            const counterStore: any = objectFactory.getInstance<any>(OTPCounters).memoryStore;
            const client = agent(server.getApplication());

            for (const crafted of [
                `elevate:${user.uid}`,
                `otp:user:${user.uid}`,
                `otp:issue:${user.uid}`,
                `otp:verify:${user.uid}`,
                "ip:10.9.8.7",
            ]) {
                // Phase 1 of MFA takes the id from the body, so it can carry a colon.
                expectRefused(await client.post(mfaUrl).send({ id: crafted, password: "wrong" }));

                const lower = crafted.toLowerCase();
                expect(limiterStore.load(`ratelimit:${lower}`)).toBeUndefined();
                expect(limiterStore.load(`ratelimit:id:${lower}`)).toBeDefined();
                expect(counterStore.load(`auth:otp:${lower}`)).toBeUndefined();
            }
        });

        it("Counts each purpose's allowance separately for the same id.", async () => {
            const { user, alias } = await createVictim();
            const client = agent(server.getApplication());
            const jwt = await login(client, user.uid);
            const send = messagingUtils.sendEmail as any;
            send.mockClear();

            // Spend the whole elevation allowance for this user (5 per address) ...
            for (let i = 0; i < 5; i++) {
                expect((await client.post(baseUrl).set("Authorization", "jwt " + jwt).send({ methodId: alias.uid })).status)
                    .toBeLessThan(300);
            }
            expect(
                throttled(await client.post(baseUrl).set("Authorization", "jwt " + jwt).send({ methodId: alias.uid })),
            ).toBe(true);
            expect(send).toHaveBeenCalledTimes(5);

            // ... without touching MFA, which uses the very same id.
            const mfa = agent(server.getApplication());
            expect((await mfa.get(mfaUrl).set("Authorization", basicAuth(user.uid))).status).toBeLessThan(300);
            expect((await mfa.post(mfaUrl).send({ id: user.uid, methodId: alias.uid })).status).toBeLessThan(300);
        });
    });

    describe("lockout of code sign-in", () => {
        it("Does not spend a contact's verification budget on guesses made without a code having been sent.", async () => {
            const { alias } = await createVictim();
            const attacker = agent(server.getApplication());

            // Far more than the 20 per hour the budget allows.
            for (let i = 0; i < 40; i++) {
                const result = await attacker.post(otpUrl).send({ id: alias.uid, token: "ABC234" });
                expect(result.status).toBe(401);
                expect(throttled(result)).toBe(false);
            }

            // The contact's owner signs in normally.
            const owner = agent(server.getApplication());
            expect((await owner.post(otpUrl).send({ id: alias.uid })).status).toBeLessThan(300);
            const result = await owner.post(otpUrl).send({ id: alias.uid, token: sentCode() });
            expect(result.status).toBeLessThan(300);
            expect(result.body).toHaveProperty("token");
        });

        it("Does not spend it on guesses against a code that was sent for something else.", async () => {
            const { alias } = await createVictim();
            const attacker = agent(server.getApplication());
            expect((await attacker.post(`${registrationUrl}/start`).send({ email: `${uuid.v4()}@example.com` })).status)
                .toBe(200);

            for (let i = 0; i < 30; i++) {
                const result = await attacker.post(otpUrl).send({ id: alias.uid, token: "ABC234" });
                expect(throttled(result)).toBe(false);
            }
            const owner = agent(server.getApplication());
            expect((await owner.post(otpUrl).send({ id: alias.uid })).status).toBeLessThan(300);
            expect((await owner.post(otpUrl).send({ id: alias.uid, token: sentCode() })).status).toBeLessThan(300);
        });
    });

    describe("with a Redis-backed session store", () => {
        // With Redis every request is handed its own JSON copy of the session and the last write wins. This swaps the
        // session store for the real `RedisSessionStore` over an in-memory client that is slow enough for parallel
        // requests to overlap, which the default in-process store (one shared object) hides, and points the one-time
        // code counters at the same Redis, as a deployment with a `cache` connection has them.
        let manager: any;
        let originalStore: any;
        let counters: any;
        let originalConnMgr: any;
        let redis: FakeRedisClient;

        beforeEach(() => {
            redis = new FakeRedisClient(5);
            manager = objectFactory.getInstance(SessionManager);
            originalStore = manager.store;
            manager.store = new RedisSessionStore(redis as any);
            counters = objectFactory.getInstance(OTPCounters);
            originalConnMgr = counters.connMgr;
            counters.connMgr = { connections: new Map([["cache", redis]]) };
        });

        afterEach(() => {
            manager.store = originalStore;
            counters.connMgr = originalConnMgr;
        });

        const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

        /** The key of the one session stored, once its (asynchronous) save has landed. */
        const sessionKey = async (): Promise<string> => {
            for (let i = 0; i < 200; i++) {
                const keys = [...redis.values.keys()].filter((k) => k.startsWith("session:"));
                if (keys.length === 1) {
                    return keys[0];
                }
                await pause(5);
            }
            throw new Error("No session was stored.");
        };

        /** Waits for the stored session to satisfy `done`. */
        const settled = async (key: string, done: (session: any) => boolean): Promise<void> => {
            for (let i = 0; i < 200; i++) {
                if (done(JSON.parse(redis.values.get(key) ?? "{}"))) {
                    return;
                }
                await pause(5);
            }
            throw new Error("The session never settled.");
        };

        /** A user at MFA phase 2 with a code sent: the client, the code, and the stored session to replay. */
        const mfaWithCode = async function () {
            const { user, alias } = await createVictim();
            const client = agent(server.getApplication());
            expect((await client.get(mfaUrl).set("Authorization", basicAuth(user.uid))).status).toBeLessThan(300);
            expect((await client.post(mfaUrl).send({ id: user.uid, methodId: alias.uid })).status).toBeLessThan(300);
            return { user, alias, client, code: sentCode() };
        };

        /** A user with a real session at elevation with a code sent. */
        const elevationWithCode = async function () {
            const { user, alias } = await createVictim();
            const client = agent(server.getApplication());
            const jwt = await login(client, user.uid);
            expect((await client.post(baseUrl).set("Authorization", "jwt " + jwt).send({ methodId: alias.uid })).status)
                .toBeLessThan(300);
            return { user, alias, client, jwt, code: sentCode() };
        };

        it("Really does hand parallel requests independent copies of the session.", async () => {
            const store: any = manager.store;
            await store.save("s", { otp: { attempts: 0 } }, 60);
            const [a, b] = await Promise.all([store.load("s"), store.load("s")]);
            a.otp.attempts = 3;
            expect(b.otp.attempts).toBe(0);
        });

        it("Keeps the counters in Redis, with commands available since Redis 7.", async () => {
            const { alias, client, code } = await requestSignInCode();
            expect((await client.post(otpUrl).send({ id: alias.uid, token: code })).status).toBeLessThan(300);

            const keys = [...redis.values.keys()].filter((k) => k.startsWith("auth:otp:"));
            expect(keys.some((k) => k.startsWith("auth:otp:attempts:"))).toBe(true);
            expect(keys.some((k) => k.startsWith("auth:otp:used:"))).toBe(true);
            expect(keys.some((k) => k.startsWith("auth:otp:issue:login:"))).toBe(true);
            expect(new Set(redis.commands)).toEqual(new Set(["GET", "SETEX", "SET", "EXEC"]));
        });

        it("Does not let parallel wrong guesses outrun maxAttempts.", async () => {
            const { alias, client, code } = await requestSignInCode();

            const guesses = await Promise.all(
                Array.from({ length: 12 }, () => client.post(otpUrl).send({ id: alias.uid, token: wrong(code) })),
            );
            for (const guess of guesses) {
                expect(guess.status).toBe(401);
            }

            // Whatever the racing writes left in the session, the code is spent: 12 guesses were made against 5.
            const result = await client.post(otpUrl).send({ id: alias.uid, token: code });
            expectRefused(result);
        });

        it("Redeems a sign-in code exactly once when the right code is submitted in parallel.", async () => {
            const { alias, client, code } = await requestSignInCode();

            const results = await Promise.all(
                Array.from({ length: 6 }, () => client.post(otpUrl).send({ id: alias.uid, token: code })),
            );

            expect(results.filter((r) => r.status < 300)).toHaveLength(1);
            expect(results.filter((r) => r.status === 401)).toHaveLength(5);
            // And not again afterwards.
            expectRefused(await client.post(otpUrl).send({ id: alias.uid, token: code }));
        });

        it("Refuses a sign-in code replayed after a stale session write-back brings the challenge back.", async () => {
            const { alias, client, code } = await requestSignInCode();
            const key = await sessionKey();
            // What a slow request that read the session before the code was redeemed would write back afterwards.
            const stale = redis.values.get(key)!;
            expect(JSON.parse(stale).otp).toBeDefined();

            const first = await client.post(otpUrl).send({ id: alias.uid, token: code });
            expect(first.status).toBeLessThan(300);
            await settled(key, (session) => !session.otp);

            redis.values.set(key, stale);
            expect(JSON.parse(redis.values.get(key)!).otp).toBeDefined();
            const replay = await client.post(otpUrl).send({ id: alias.uid, token: code });

            expectRefused(replay);
            expect([first, replay].filter((r) => r.status < 300)).toHaveLength(1);
        });

        it("Completes MFA exactly once when the right code is submitted in parallel.", async () => {
            const { user, client, code } = await mfaWithCode();

            const results = await Promise.all(
                Array.from({ length: 6 }, () => client.post(mfaUrl).send({ id: user.uid, token: code })),
            );

            expect(results.filter((r) => r.status < 300)).toHaveLength(1);
            expect(results.filter((r) => r.status >= 400)).toHaveLength(5);
            expectRefused(await client.post(mfaUrl).send({ id: user.uid, token: code }));
        });

        it("Refuses an MFA code replayed after a stale session write-back brings the challenge back.", async () => {
            const { user, client, code } = await mfaWithCode();
            const key = await sessionKey();
            await settled(key, (session) => !!session.otp && !!session.mfaPendingUid);
            const stale = redis.values.get(key)!;

            const first = await client.post(mfaUrl).send({ id: user.uid, token: code });
            expect(first.status).toBeLessThan(300);
            await settled(key, (session) => !session.otp && !session.mfaPendingUid);

            redis.values.set(key, stale);
            const replay = await client.post(mfaUrl).send({ id: user.uid, token: code });

            expectRefused(replay);
            expect([first, replay].filter((r) => r.status < 300)).toHaveLength(1);
        });

        it("Does not let parallel wrong MFA codes outrun maxAttempts.", async () => {
            const { user, client, code } = await mfaWithCode();

            const guesses = await Promise.all(
                Array.from({ length: 12 }, () => client.post(mfaUrl).send({ id: user.uid, token: wrong(code) })),
            );
            for (const guess of guesses) {
                expectRefused(guess);
            }
            // The code is spent, so even the right one is refused.
            expectRefused(await client.post(mfaUrl).send({ id: user.uid, token: code }));
        });

        it("Elevates exactly once when the right code is submitted in parallel.", async () => {
            const { client, jwt, code } = await elevationWithCode();

            const results = await Promise.all(
                Array.from({ length: 6 }, () =>
                    client.post(baseUrl).set("Authorization", "jwt " + jwt).send({ token: code }),
                ),
            );

            expect(results.filter((r) => r.status < 300)).toHaveLength(1);
            expect(results.filter((r) => r.status >= 400)).toHaveLength(5);
        });

        it("Refuses an elevation code replayed after a stale session write-back brings the challenge back.", async () => {
            const { client, jwt, code } = await elevationWithCode();
            const key = await sessionKey();
            await settled(key, (session) => !!session.otp && !!session.elevateUid);
            const stale = redis.values.get(key)!;

            const first = await client.post(baseUrl).set("Authorization", "jwt " + jwt).send({ token: code });
            expect(first.status).toBeLessThan(300);
            await settled(key, (session) => !session.otp && !session.elevateUid);

            redis.values.set(key, stale);
            const replay = await client.post(baseUrl).set("Authorization", "jwt " + jwt).send({ token: code });

            expect(replay.status).toBe(401);
            expect(replay.body?.user?.elevated).toBeUndefined();
            expect([first, replay].filter((r) => r.status < 300)).toHaveLength(1);
        });

        it("Does not let parallel wrong elevation codes outrun maxAttempts.", async () => {
            const { client, jwt, code } = await elevationWithCode();

            const guesses = await Promise.all(
                Array.from({ length: 12 }, () =>
                    client.post(baseUrl).set("Authorization", "jwt " + jwt).send({ token: wrong(code) }),
                ),
            );
            for (const guess of guesses) {
                expect(guess.status).toBe(401);
            }
            const result = await client.post(baseUrl).set("Authorization", "jwt " + jwt).send({ token: code });
            expect(result.status).toBe(401);
        });
    });
});
