///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for ClientAuthUtils — no HTTP server, no database.
import { HttpRequest } from "@rapidrest/service-core";
import { ClientAuthUtils } from "../../src/auth/ClientAuthUtils.js";
import { Client, ClientType, TokenEndpointAuthMethod } from "../../src/models/types.js";

function makeRequest(overrides: Partial<HttpRequest> = {}): HttpRequest {
    return {
        method: "POST",
        path: "/oauth/token",
        url: "/oauth/token",
        headers: {},
        params: {},
        query: {},
        body: {},
        cookies: {},
        signedCookies: {},
        socket: {},
        ...overrides,
    };
}

function makeMockRepo(clients: Client[]) {
    return {
        findOne: vi.fn(async (clientId: string) => clients.find((c) => c.clientId === clientId)),
    };
}

async function hashSecret(secret: string): Promise<string> {
    const argon = await import("argon2");
    return argon.hash(secret);
}

describe("ClientAuthUtils Tests", () => {
    it("Authenticates a confidential client via an Authorization: Basic header.", async () => {
        const clientSecretHash = await hashSecret("s3cret");
        const client: Client = {
            uid: "client-1",
            dateCreated: new Date(),
            dateModified: new Date(),
            version: 0,
            clientId: "abc123",
            clientSecretHash,
            clientType: ClientType.CONFIDENTIAL,
            clientName: "Test App",
            redirectUris: [],
            grantTypes: [],
            responseTypes: [],
            scope: "",
            tokenEndpointAuthMethod: TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            requirePkce: false,
            firstParty: false,
        };
        const repo = makeMockRepo([client]);
        const utils = new ClientAuthUtils(repo as any);
        const basic = Buffer.from("abc123:s3cret").toString("base64");
        const req = makeRequest({ headers: { authorization: `Basic ${basic}` } });

        const result = await utils.authenticateClient(req);

        expect(result.clientId).toBe("abc123");
    });

    it("Authenticates a confidential client via client_secret_post body parameters.", async () => {
        const clientSecretHash = await hashSecret("s3cret");
        const client: Client = {
            uid: "client-1",
            dateCreated: new Date(),
            dateModified: new Date(),
            version: 0,
            clientId: "abc123",
            clientSecretHash,
            clientType: ClientType.CONFIDENTIAL,
            clientName: "Test App",
            redirectUris: [],
            grantTypes: [],
            responseTypes: [],
            scope: "",
            tokenEndpointAuthMethod: TokenEndpointAuthMethod.CLIENT_SECRET_POST,
            requirePkce: false,
            firstParty: false,
        };
        const repo = makeMockRepo([client]);
        const utils = new ClientAuthUtils(repo as any);
        const req = makeRequest({ body: { grant_type: "client_credentials", client_id: "abc123", client_secret: "s3cret" } });

        const result = await utils.authenticateClient(req);

        expect(result.clientId).toBe("abc123");
    });

    it("Authenticates a public client with tokenEndpointAuthMethod 'none' without a secret.", async () => {
        const client: Client = {
            uid: "client-2",
            dateCreated: new Date(),
            dateModified: new Date(),
            version: 0,
            clientId: "public-app",
            clientType: ClientType.PUBLIC,
            clientName: "Mobile App",
            redirectUris: [],
            grantTypes: [],
            responseTypes: [],
            scope: "",
            tokenEndpointAuthMethod: TokenEndpointAuthMethod.NONE,
            requirePkce: true,
            firstParty: true,
        };
        const repo = makeMockRepo([client]);
        const utils = new ClientAuthUtils(repo as any);
        const req = makeRequest({ body: { grant_type: "authorization_code", client_id: "public-app" } });

        const result = await utils.authenticateClient(req);

        expect(result.clientId).toBe("public-app");
    });

    it("Rejects a request with no client_id at all.", async () => {
        const repo = makeMockRepo([]);
        const utils = new ClientAuthUtils(repo as any);
        const req = makeRequest();

        await expect(utils.authenticateClient(req)).rejects.toThrow(/Invalid client/);
    });

    it("Rejects an unknown client_id.", async () => {
        const repo = makeMockRepo([]);
        const utils = new ClientAuthUtils(repo as any);
        const req = makeRequest({ body: { client_id: "does-not-exist", client_secret: "whatever" } });

        await expect(utils.authenticateClient(req)).rejects.toThrow(/Invalid client/);
    });

    it("Rejects a disabled client.", async () => {
        const clientSecretHash = await hashSecret("s3cret");
        const client: Client = {
            uid: "client-1",
            dateCreated: new Date(),
            dateModified: new Date(),
            version: 0,
            clientId: "abc123",
            clientSecretHash,
            clientType: ClientType.CONFIDENTIAL,
            clientName: "Test App",
            redirectUris: [],
            grantTypes: [],
            responseTypes: [],
            scope: "",
            tokenEndpointAuthMethod: TokenEndpointAuthMethod.CLIENT_SECRET_POST,
            requirePkce: false,
            firstParty: false,
            disabled: true,
        };
        const repo = makeMockRepo([client]);
        const utils = new ClientAuthUtils(repo as any);
        const req = makeRequest({ body: { client_id: "abc123", client_secret: "s3cret" } });

        await expect(utils.authenticateClient(req)).rejects.toThrow(/Invalid client/);
    });

    it("Rejects a confidential client presenting the wrong secret.", async () => {
        const clientSecretHash = await hashSecret("s3cret");
        const client: Client = {
            uid: "client-1",
            dateCreated: new Date(),
            dateModified: new Date(),
            version: 0,
            clientId: "abc123",
            clientSecretHash,
            clientType: ClientType.CONFIDENTIAL,
            clientName: "Test App",
            redirectUris: [],
            grantTypes: [],
            responseTypes: [],
            scope: "",
            tokenEndpointAuthMethod: TokenEndpointAuthMethod.CLIENT_SECRET_POST,
            requirePkce: false,
            firstParty: false,
        };
        const repo = makeMockRepo([client]);
        const utils = new ClientAuthUtils(repo as any);
        const req = makeRequest({ body: { client_id: "abc123", client_secret: "wrong-secret" } });

        await expect(utils.authenticateClient(req)).rejects.toThrow(/Invalid client/);
    });

    it("Rejects a confidential client with no secret configured when no secret is presented.", async () => {
        const client: Client = {
            uid: "client-1",
            dateCreated: new Date(),
            dateModified: new Date(),
            version: 0,
            clientId: "abc123",
            clientType: ClientType.CONFIDENTIAL,
            clientName: "Test App",
            redirectUris: [],
            grantTypes: [],
            responseTypes: [],
            scope: "",
            tokenEndpointAuthMethod: TokenEndpointAuthMethod.CLIENT_SECRET_POST,
            requirePkce: false,
            firstParty: false,
        };
        const repo = makeMockRepo([client]);
        const utils = new ClientAuthUtils(repo as any);
        const req = makeRequest({ body: { client_id: "abc123" } });

        await expect(utils.authenticateClient(req)).rejects.toThrow(/Invalid client/);
    });

    it("Rejects a client registered with private_key_jwt as not yet supported.", async () => {
        const client: Client = {
            uid: "client-1",
            dateCreated: new Date(),
            dateModified: new Date(),
            version: 0,
            clientId: "abc123",
            clientType: ClientType.CONFIDENTIAL,
            clientName: "Test App",
            redirectUris: [],
            grantTypes: [],
            responseTypes: [],
            scope: "",
            tokenEndpointAuthMethod: TokenEndpointAuthMethod.PRIVATE_KEY_JWT,
            requirePkce: false,
            firstParty: false,
        };
        const repo = makeMockRepo([client]);
        const utils = new ClientAuthUtils(repo as any);
        const req = makeRequest({ body: { client_id: "abc123" } });

        await expect(utils.authenticateClient(req)).rejects.toThrow(/private_key_jwt/);
    });
});
