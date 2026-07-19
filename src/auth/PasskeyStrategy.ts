////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import type { JWTUser } from "@rapidrest/core";
import { AuthResult, AuthStrategy, HttpRequest, HttpResponse } from "@rapidrest/service-core";
import { PasskeyConfig, PasskeyTransport, StoredPasskeyCredential } from "./types.js";
import { generatePasskeyChallenge, isPasskeyResponse, verifyPasskeyChallenge } from "./shared.js";

/**
 * Describes the configuration options that can be used to initialize PasskeyStrategy.
 *
 * @author Jean-Philippe Steinmetz
 */
export class PasskeyStrategyOptions {
    /**
     * The relying party configuration to use for this strategy.
     */
    public config: PasskeyConfig;

    constructor(config: PasskeyConfig) {
        this.config = config;
    }

    /**
     * Retrieves a previously-registered credential by its ID. Returns `undefined` if no credential
     * with that ID is known.
     * NOTE: You must override this function when using this strategy.
     */
    public async getCredentialById(credentialId: string): Promise<StoredPasskeyCredential | undefined> {
        throw new Error("Did you forget to override PasskeyStrategyOptions.getCredentialById?");
    }

    /**
     * Retrieves all credentials registered for the given user. Used to build the `allowCredentials`
     * list when a login ceremony is started with a known user hint.
     * NOTE: You must override this function when using this strategy.
     * @param id The unique identifier of the user or alias.
     */
    public async getCredentials(id: string): Promise<StoredPasskeyCredential[]> {
        throw new Error("Did you forget to override PasskeyStrategyOptions.getCredentials?");
    }

    /**
     * Persists the updated signature counter for the given credential after a successful
     * authentication. Must be called on every successful login to guard against cloned authenticators.
     * NOTE: You must override this function when using this strategy.
     */
    public async updateCredentialCounter(credentialId: string, newCounter: number): Promise<void> {
        throw new Error("Did you forget to override PasskeyStrategyOptions.updateCredentialCounter?");
    }

    /**
     * Retrieves the user data for the given unique identifier after authentication has completed successfully.
     * NOTE: You must override this function when using this strategy.
     * @param id The unique identifier of the user that has been successfully authenticated.
     */
    public getUser(uid: string): Promise<JWTUser | undefined> {
        throw new Error("Did you forget to override TOTPStrategyOptions.getUser?");
    }
}

/**
 * Implements an authentication strategy for performing WebAuthn/Passkey (FIDO2) login.
 *
 * The login flow has two phases:
 *
 * 1. Challenge - The client requests a challenge. A random challenge is generated and stored in the
 * session, and the resulting options are returned for use with
 * `navigator.credentials.get()`.
 * 2. Verify - The client submits the signed assertion response. The response is verified against the
 * stored challenge and the credential's public key, the credential's signature counter is updated,
 * and the associated user is resolved via `verify()`.
 *
 * NOTE: Requires session support!
 *
 * @author Jean-Philippe Steinmetz <rapidrests@gmail.com>
 */
export class PasskeyStrategy implements AuthStrategy {
    public readonly name: string = "passkey";
    private options: PasskeyStrategyOptions;

    constructor(options: PasskeyStrategyOptions) {
        this.options = options;
    }

    public async authenticate(
        req: HttpRequest,
        res: HttpResponse,
        required?: boolean,
    ): Promise<AuthResult | undefined> {
        if (req.body?.id || req.body?.response) {
            return await this.verify(req, required);
        } else {
            return await this.challenge(req, res);
        }
    }

    public authenticateSync(req: HttpRequest, res: HttpResponse, required?: boolean): AuthResult | undefined {
        throw new Error("Not supported. This auth strategy must be used asynchronously.");
    }

    /**
     * Begins a login ceremony: generates a challenge, stores it in the session, and writes the
     * resulting options directly to the response for the client to pass to `navigator.credentials.get()`.
     *
     * @param req The source HTTP request. May optionally carry a `uid` query parameter to scope the
     * allowed credentials to a known user; omitted entirely for a discoverable/"usernameless" flow.
     * @param res The response to write the generated options to.
     */
    protected async challenge(req: HttpRequest, res: HttpResponse): Promise<undefined> {
        if (!req.session) {
            throw new Error(
                "PasskeyStrategy requires session support. Configure the `session` config block so the " +
                    "session middleware is registered.",
            );
        }
        if (!res) {
            throw new Error("PasskeyStrategy requires a response object to begin a ceremony.");
        }

        // If a uid hint is given, scope allowCredentials to that user's registered credentials. If
        // the hint resolves to zero credentials, allowCredentials is left undefined (same as the
        // no-hint case) rather than sent as an empty list. Otherwise the response shape would leak
        // whether a given uid has any passkeys registered, a user-enumeration side channel.
        // NOTE: scoping allowCredentials to a uid hint necessarily discloses to an unauthenticated
        // caller whether the given uid has any registered passkeys (and their credential IDs/
        // transports). The same trade-off inherent to any "enter your username first" login flow.
        // Only the zero-credential case is equalized with the no-hint case below (both leave
        // allowCredentials undefined), so a nonexistent/passkey-less account can't be trivially
        // distinguished from one with zero credentials; an account that DOES have credentials
        // remains distinguishable from one that doesn't by design. Callers that need to avoid this
        // entirely (e.g. a public-facing login form) should not wire a client-suppliable uid hint
        // through to this endpoint at all — rely purely on the discoverable/"usernameless" flow by
        // omitting the hint, and consider rate-limiting this endpoint regardless.
        const uidHint: string | undefined = req.query?.uid as string | undefined;
        let allowCredentials: { id: string; transports?: PasskeyTransport[] }[] | undefined = undefined;
        if (uidHint) {
            const credentials: StoredPasskeyCredential[] = await this.options.getCredentials(uidHint);
            if (credentials.length > 0) {
                allowCredentials = credentials.map((c) => ({ id: c.id, transports: c.transports }));
            }
        }

        const result = await generatePasskeyChallenge(this.options.config, req, allowCredentials);
        res.status(200);
        res.json(result);
        return undefined;
    }

    /**
     * Finishes a login ceremony: verifies the client-submitted assertion response against the
     * stored challenge and credential, updates the credential's signature counter, and resolves the
     * associated user.
     *
     * @param req The source HTTP request, carrying the assertion response in its body.
     * @param required Set to `true` if authentication is required to pass, otherwise set to `false`.
     */
    protected async verify(req: HttpRequest, required?: boolean): Promise<AuthResult | undefined> {
        if (!req.session) {
            throw new Error(
                "PasskeyStrategy requires session support. Configure the `session` config block so the " +
                    "session middleware is registered.",
            );
        }
        if (!req.session.challenge) {
            throw new Error("No passkey ceremony in progress for this session.");
        }

        // The challenge is single-use regardless of outcome — cleared as soon as it's read, before
        // verification is even attempted, rather than only on the success path.
        const expectedChallenge: string = req.session.challenge;
        delete req.session.challenge;

        // Strict shape validation before touching storage or SimpleWebAuthn — a malformed finish
        // attempt should fail with a clean, actionable error rather than crashing deep inside the
        // verification library with a confusing low-level error. This alone doesn't reveal whether
        // any particular account/credential exists, so it's kept distinct from the generic failure
        // message below.
        if (!isPasskeyResponse(req.body)) {
            throw new Error("Malformed passkey authentication response.");
        }

        // Every failure from here on is reported with the same generic message, regardless of
        // whether the credential ID is unknown, the signature failed to verify, the counter
        // regressed, or the resolved user was rejected by verify() — distinguishing between these
        // would let a caller enumerate which credential IDs/accounts are registered on this server.
        const genericFailure = (): Error => new Error("Passkey authentication failed.");

        const credential: StoredPasskeyCredential | undefined = await this.options.getCredentialById(req.body.id);
        if (!credential) {
            throw genericFailure();
        }

        const result = await verifyPasskeyChallenge(credential, this.options.config, expectedChallenge, req.body);
        if (!result.verified) {
            throw genericFailure();
        }

        // Counter regression check. SimpleWebAuthn deliberately does not enforce counter monotonicity
        // itself (many multi-device/backed-up passkeys always report 0 and would otherwise be
        // permanently locked out) — a non-zero counter that fails to exceed the stored value is the
        // signal of a cloned authenticator per the WebAuthn spec's guidance.
        const newCounter: number = result.authenticationInfo.newCounter;
        if (newCounter !== 0 && newCounter <= credential.counter) {
            throw genericFailure();
        }
        await this.options.updateCredentialCounter(credential.id, newCounter);

        const user: JWTUser | undefined = await this.options.getUser(credential.uid);
        if (user) {
            return {
                data: req.body,
                method: this.name,
                payload: result.authenticationInfo,
                user,
            };
        }

        if (required) {
            throw genericFailure();
        }
        return undefined;
    }
}
