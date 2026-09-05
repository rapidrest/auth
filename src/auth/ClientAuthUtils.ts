///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ApiError } from "@rapidrest/core";
import { ApiErrors, HttpRequest, RepoUtils } from "@rapidrest/service-core";
import { Client, TokenEndpointAuthMethod } from "../models/types.js";
import { getBasicData, getRequestData, importArgon2, verifyDummyPassword } from "./shared.js";

/**
 * Manages client authentication for the token endpoint (RFC 6749 §2.3), where the caller being
 * authenticated is an application, not a person. Deliberately not modeled as an `AuthStrategy`: the token
 * endpoint must resolve the calling `Client` *before* it can decide how to interpret the rest of the
 * request (e.g. the `client_credentials` grant has no resource owner at all), which doesn't fit
 * `AuthStrategy.authenticate()`'s `JWTUser`-shaped result.
 *
 * Not exported from `src/auth/index.ts` — like `TokenUtils`, this is an internal service constructed by a
 * route's `@Init` hook (`this._objectFactory.newInstance(ClientAuthUtils, {name, args: [clientRepo]})`),
 * since the concrete `Client` model class differs between the Mongo and SQL datastores.
 *
 * @author Jean-Philippe Steinmetz
 */
export class ClientAuthUtils {
    private readonly repo: RepoUtils<Client>;

    constructor(repo: RepoUtils<Client>) {
        this.repo = repo;
    }

    /**
     * Authenticates the client making the given request, supporting `client_secret_basic` (an
     * `Authorization: Basic` header) and `client_secret_post` (`client_id`/`client_secret` request body
     * parameters). A `PUBLIC` client configured with `tokenEndpointAuthMethod: "none"` only needs to
     * present a valid, non-disabled `clientId` — no secret is checked, since PKCE is what authenticates
     * the authorization grant itself for such a client.
     *
     * Every failure — unknown `clientId`, wrong secret, disabled client — throws the same error, so a
     * caller can't enumerate valid client ids by observing a different failure reason.
     *
     * @param req The request to authenticate the client of.
     * @throws `ApiError` (401) if the client cannot be authenticated, or (501) if the client is registered
     * with `private_key_jwt`, which is not yet supported.
     */
    public async authenticateClient(req: HttpRequest): Promise<Client> {
        const basic = getBasicData(req);
        // Skip `getRequestData()`'s own header search (headerKey: "") since `getBasicData()` above already
        // covers the header case — this call is only here to read `client_id`/`client_secret` out of the body.
        const { payload } = getRequestData(req, "");

        const clientId: string | undefined = basic?.id ?? payload?.client_id;
        const clientSecret: string | undefined = basic?.password ?? payload?.client_secret;

        const invalidClient = async (): Promise<never> => {
            // Burn an equivalent amount of time as a real secret verification so an unknown/disabled client
            // isn't distinguishable, by timing, from a known one with a wrong secret.
            await verifyDummyPassword(clientSecret ?? "");
            throw new ApiError(ApiErrors.AUTH_FAILED, 401, "Invalid client.");
        };

        if (!clientId) {
            return invalidClient();
        }

        const client: Client | undefined = await this.repo.findOne(clientId, { ignoreACL: true });
        if (!client || client.disabled) {
            return invalidClient();
        }

        if (client.tokenEndpointAuthMethod === TokenEndpointAuthMethod.PRIVATE_KEY_JWT) {
            throw new ApiError(ApiErrors.INTERNAL_ERROR, 501, "`private_key_jwt` client authentication is not yet supported.");
        }

        if (client.tokenEndpointAuthMethod === TokenEndpointAuthMethod.NONE) {
            return client;
        }

        if (!client.clientSecretHash || !clientSecret) {
            return invalidClient();
        }

        const argon = await importArgon2();
        const valid: boolean = await argon.verify(client.clientSecretHash, clientSecret);
        if (!valid) {
            return invalidClient();
        }

        return client;
    }
}
