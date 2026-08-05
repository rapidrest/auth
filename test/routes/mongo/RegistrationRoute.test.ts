///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
import config from "../../config.js";
import { agent, request } from "@rapidrest/service-core/test";
import { MongoConnection, MongoRepository, Server, ObjectFactory, ConnectionManager } from "@rapidrest/service-core";
import { Logger, MessagingUtils } from "@rapidrest/core";
import * as uuid from "uuid";
import { UserMongo } from "../../../src/models/mongo/UserMongo.js";
import { MongoMemoryServer } from "mongodb-memory-server";
import { AliasMongo } from "../../../src/models/mongo/AliasMongo.js";
import { AliasType } from "../../../src/models/types.js";

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:RegistrationMongo Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-mongo", logger, objectFactory });
    const baseUrl = "/mongo/registration";
    let userRepo: MongoRepository<UserMongo>;
    let aclRepo: MongoRepository<any>;
    let aliasRepo: MongoRepository<AliasMongo>;
    let messagingUtils: MessagingUtils;

    beforeAll(async () => {
        await mongod.start();
        await server.start();

        const connMgr: ConnectionManager | undefined = objectFactory.getInstance(ConnectionManager);
        let conn: any = connMgr?.connections.get("acl");
        if (conn instanceof MongoConnection) {
            aclRepo = conn.getMongoRepository("AccessControlListMongo");
        }
        conn = connMgr?.connections.get("mongo");
        if (conn instanceof MongoConnection) {
            userRepo = conn.getMongoRepository("UserMongo");
            aliasRepo = conn.getMongoRepository("AliasMongo");
        } else {
            throw new Error("Could not find user connection");
        }

        messagingUtils = objectFactory.getInstance(MessagingUtils) as MessagingUtils;
    });

    afterAll(async () => {
        await server.stop();
        await mongod.stop();
        await objectFactory.destroy();
    });

    beforeEach(async () => {
        try {
            await userRepo.clear();
            await aliasRepo.clear();
        } catch (err: any) {
            // The error "ns not found" occurs when the collection doesn't exist yet. We can ignore this error.
            if (err.message !== "ns not found") {
                throw err;
            }
        }

        // No SMTP/Twilio provider is configured in the test environment, so sending would otherwise
        // reject in the background (fire-and-forget, per `BaseRegistrationRoute.start`). Stub it out and
        // use the captured call args to recover the generated token, the way the real contact would have
        // received it via e-mail/SMS.
        vi.spyOn(messagingUtils, "sendEmail").mockResolvedValue(undefined as any);
        vi.spyOn(messagingUtils, "sendSMS").mockResolvedValue(undefined as any);
    });

    it("Can register a new account by verifying an e-mail address.", async () => {
        const client = agent(server.getApplication());
        const email = `${uuid.v4()}@example.com`;

        const startResult = await client.post(`${baseUrl}/start`).send({ email });
        expect(startResult).toBeDefined();
        expect(startResult.status).toBeGreaterThanOrEqual(200);
        expect(startResult.status).toBeLessThan(300);

        const sendEmailMock = messagingUtils.sendEmail as any;
        expect(sendEmailMock).toHaveBeenCalledTimes(1);
        const token: string = sendEmailMock.mock.calls[0][1].totp;
        expect(token).toBeDefined();

        const verifyResult = await client.post(`${baseUrl}/verify`).send({ email, token });
        expect(verifyResult).toBeDefined();
        expect(verifyResult.status).toBeGreaterThanOrEqual(200);
        expect(verifyResult.status).toBeLessThan(300);
        expect(verifyResult.body).toHaveProperty("token");
        expect(verifyResult.body).toHaveProperty("user");
        expect(verifyResult.body.user.verified).toBe(true);
        expect(String(verifyResult.headers["set-cookie"])).toContain(`jwt=${verifyResult.body.token}`);

        const createdUser: UserMongo | null = await userRepo.findOne({ uid: verifyResult.body.user.uid });
        expect(createdUser).toBeDefined();

        const aliases: AliasMongo[] = await aliasRepo
            .find({ alias: email.toLowerCase(), type: AliasType.EMAIL })
            .toArray();
        expect(aliases).toHaveLength(1);
        expect(aliases[0].verified).toBe(true);
        expect(aliases[0].userUid).toBe(verifyResult.body.user.uid);
    });

    it("Can register a new account by verifying a phone number.", async () => {
        const client = agent(server.getApplication());
        const phone = "+14155552671";

        const startResult = await client.post(`${baseUrl}/start`).send({ phone });
        expect(startResult.status).toBeGreaterThanOrEqual(200);
        expect(startResult.status).toBeLessThan(300);

        const sendSMSMock = messagingUtils.sendSMS as any;
        expect(sendSMSMock).toHaveBeenCalledTimes(1);
        const token: string = sendSMSMock.mock.calls[0][1].totp;
        expect(token).toBeDefined();

        const verifyResult = await client.post(`${baseUrl}/verify`).send({ phone, token });
        expect(verifyResult.status).toBeGreaterThanOrEqual(200);
        expect(verifyResult.status).toBeLessThan(300);
        expect(verifyResult.body).toHaveProperty("token");
        expect(verifyResult.body).toHaveProperty("user");

        const aliases: AliasMongo[] = await aliasRepo.find({ alias: phone, type: AliasType.PHONE }).toArray();
        expect(aliases).toHaveLength(1);
        expect(aliases[0].verified).toBe(true);
    });

    it("Does not send a challenge or reveal that an account already exists for a verified e-mail.", async () => {
        const email = `${uuid.v4()}@example.com`;
        const user: UserMongo = await userRepo.save(new UserMongo({ roles: [], scopes: [], verified: true }));
        await aliasRepo.save(new AliasMongo({ alias: email, type: AliasType.EMAIL, userUid: user.uid, verified: true }));

        const result = await request(server.getApplication()).post(`${baseUrl}/start`).send({ email });

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(messagingUtils.sendEmail).not.toHaveBeenCalled();
    });

    it("Rejects starting registration without a valid e-mail address or phone number.", async () => {
        const result = await request(server.getApplication()).post(`${baseUrl}/start`).send({ email: "not-an-email" });

        expect(result.status).toBe(400);
    });

    it("Cannot verify with an invalid token.", async () => {
        const client = agent(server.getApplication());
        const email = `${uuid.v4()}@example.com`;

        await client.post(`${baseUrl}/start`).send({ email });

        const result = await client.post(`${baseUrl}/verify`).send({ email, token: "000000" });

        expect(result.status).toBe(400);
    });

    it("Cannot verify without first requesting a challenge (no session state).", async () => {
        const email = `${uuid.v4()}@example.com`;

        const result = await request(server.getApplication())
            .post(`${baseUrl}/verify`)
            .send({ email, token: "000000" });

        expect(result.status).toBe(400);
    });

    it("Cannot verify without an e-mail/phone or token.", async () => {
        const result = await request(server.getApplication()).post(`${baseUrl}/verify`).send({});

        expect(result.status).toBe(400);
    });
});
