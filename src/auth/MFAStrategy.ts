////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import type { JWTUser } from "@rapidrest/core";
import { AuthStrategy, HttpRequest, HttpResponse, AuthResult } from "@rapidrest/service-core";
import { OTPContact, PasskeyConfig, StoredPasskeyCredential } from "./types.js";
import {
    generateOTP,
    generatePasskeyChallenge,
    getBasicData,
    getRequestData,
    isOTPResponse,
    isPasskeyResponse,
    verifyOTP,
    verifyPasskeyChallenge,
    verifyTOTP,
} from "./shared.js";

/**
 * The different types of secondary authentication methods.
 */
export enum MFAMethodType {
    FIDO2 = "fido2",
    OTP = "otp",
    TOTP = "totp",
}

/**
 * Describes a method for performing the secondary authentication.
 */
export interface MFAMethod {
    /** The unique id of the secondary authentication method. */
    id: string;
    /** The method specific data required to perform secondary authentication. */
    data: any;
    /** The method type of contact (e.g. email, fido2, sms). */
    type: MFAMethodType;
}

/**
 * Describes the configuration options that can be used to initialize MFAStrategy.
 *
 * @author Jean-Philippe Steinmetz
 */
export class MFAStrategyOptions {
    /** The name of the header to look for when performing header based authentication. Default value is `Authorization`. */
    public headerKey: string = "authorization";
    /** The authorization scheme type when using header based authentication. Default value is `basic`. */
    public headerScheme: string = "basic";
    /**
     * The FIDO2/Passkey configuration to use when a FIDO2 secondary auth is used.
     */
    public fidoConfig?: PasskeyConfig;
    /**
     * Set to `true` to require that user's must provide secondary authentication to succeed, otherwise set to
     * `false`. Default is `true`.
     */
    public require2FA: boolean = true;
    /**
     * Optional hook invoked with the claimed identifier before password/OTP verification. Implementations
     * should throw to reject the request once a caller-defined attempt threshold has been exceeded (see
     * `RateLimiter`). A no-op when not provided.
     */
    public checkRateLimit?(identifier: string, req: HttpRequest): Promise<void>;
    /**
     * Retrieves a previously-registered FIDO2 credential by its ID, for verifying a FIDO2 secondary
     * authentication challenge response. Returns `undefined` if no credential with that ID is known.
     * NOTE: You must override this function to support the `FIDO2` secondary authentication method.
     */
    public getCredentialById(credentialId: string): Promise<StoredPasskeyCredential | undefined> {
        throw new Error("Did you forget to override MFAStrategyOptions.getCredentialById?");
    }
    /**
     * Retrieves the user's secondary authentication method for a given id. Implementations must only return a
     * method that actually belongs to `uid` — this is the authorization boundary that prevents one user's 2FA
     * challenge from being triggered/consumed using another user's authentication method.
     * NOTE: You must override this function when using this strategy.
     * @param id The unique id of the secondary auth method to retrieve.
     * @param uid The unique id of the user the method must belong to.
     */
    public getMethod(id: string, uid: string): Promise<MFAMethod | undefined> {
        throw new Error("Did you forget to override MFAStrategyOptions.getContact?");
    }
    /**
     * Retrieves the list of secondary authentication methods for the user with the given id.
     * NOTE: You must override this function when using this strategy.
     * @param id The unique id of the user.
     */
    public getMethods(id: string): Promise<MFAMethod[]> {
        throw new Error("Did you forget to override MFAStrategyOptions.getContacts?");
    }
    /**
     * Retrieves the user data for the given unique identifier after authentication has completed successfully.
     * NOTE: You must override this function when using this strategy.
     * @param id The unique identifier of the user that has been successfully authenticated.
     */
    public getUser(uid: string): Promise<JWTUser | undefined> {
        throw new Error("Did you forget to override MFAStrategyOptions.getUsers?");
    }
    /**
     * Persists the updated signature counter for the given FIDO2 credential after a successful
     * challenge. Must be called on every successful FIDO2 secondary authentication to guard against
     * cloned authenticators.
     * NOTE: You must override this function to support the `FIDO2` secondary authentication method.
     */
    public updateCredentialCounter(credentialId: string, newCounter: number): Promise<void> {
        throw new Error("Did you forget to override MFAStrategyOptions.updateCredentialCounter?");
    }
    /**
     * Persists the given time step as the last one successfully used for the identified TOTP
     * secret, so a captured/replayed token within its validity window can't be used to authenticate
     * a second time. Optional — when omitted, successfully-verified TOTP codes remain valid for
     * reuse until they naturally expire.
     * @param uid The unique id of the secondary auth method (== the underlying secret's id) that was verified.
     * @param timeStep The RFC 6238 time step at which the token was verified.
     */
    public updateSecretTimeStep?(uid: string, timeStep: number): Promise<void>;
    /**
     * Sends a notification to the specified contact with the provided MFA code.
     * NOTE: You must override this function when using this strategy.
     * @param contact The contact to send the MFA code to.
     * @param totp The MFA code to send to the user.
     */
    public notifyContact(contact: OTPContact, totp: string): Promise<void> {
        throw new Error("Did you forget to override MFAStrategyOptions.notify?");
    }
    /**
     * Called to verify the provided user's id and password.
     * NOTE: You must override this function when using this strategy.
     * @param id The unique id of the user whose password must be verified.
     * @param password The password of the user to verify.
     * @returns The successfully verified user data, otherwise `undefined`.
     */
    public verify(id: string, password: string): Promise<JWTUser | undefined> {
        throw new Error("Did you forget to override MFAStrategyOptions.verify?");
    }
}

/**
 * Implements a multi-factory authentication (MFA) strategy that performs basic id and password verification, followed
 * by a secondary authentication. This strategy requires an existing user account to have already registered a valid
 * password that will be validated as well as at least one secondary authentication method.
 *
 * Supported secondary authentication (2FA) methods:
 *
 * * `FIDO2` - A hardware-based key challenge exchange that the user has access to (e.g. Yubikey, Passkey, etc).
 * * `OTP` - A One Time Password (OTP) sent to one of the user's verified contacts.
 * * `TOTP` - A Time-Based One Time Password (TOTP) configured on a device the user owns or has access to.
 *
 * The login flow has three phases:
 *
 * 1. Verify Basic - The client sends a request with `Authorization` header containing the user's id and password. The
 * server returns `{ uid, methods }`: the user's internal uid (needed to identify subsequent phase 2/3 requests as
 * this session's, regardless of what login identifier — email, alias, etc. — was used for phase 1) and the list of
 * available secondary authentication methods.
 * 2. Challenge - The client requests a selected 2FA challenge, submitting the `uid` from phase 1 as `id` and
 * identifying the method by `methodId`. If `FIDO2` is selected, a WebAuthn challenge scoped to that credential is
 * generated and stored in the session. If `OTP` is selected, a challenge token is generated, stored in the
 * session, and sent to the selected verified contact. If `TOTP` is selected, no challenge/notification is
 * generated or sent — the client's authenticator app already has the current code — but the selection is still
 * recorded in the session so phase 3 knows which secret to verify against.
 * 3. Verify - The client submits the completed 2FA challenge. The challenge is verified against the one stored in the
 * session, and the associated user is resolved using the `getUser()` callback.
 *
 * @author Jean-Philippe Steinmetz <rapidrests@gmail.com>
 */
export class MFAStrategy implements AuthStrategy {
    public readonly name: string = "mfa";
    private options: MFAStrategyOptions;

    constructor(options: MFAStrategyOptions) {
        this.options = options;
    }

    public async authenticate(
        req: HttpRequest,
        res: HttpResponse,
        required?: boolean,
    ): Promise<AuthResult | undefined> {
        const { data, payload } = getRequestData(req);

        if (isOTPResponse(payload)) {
            // OTP and TOTP submissions share the exact same `{id, token}` shape — route based on
            // which method was selected during phase 2's challenge(), recorded in the session.
            const user: JWTUser | undefined = req.session?.mfaMethodId
                ? await this.verifyTOTP(payload, req, res)
                : await this.verifyOTP(payload, req, res);
            if (user) {
                return {
                    data,
                    method: this.name,
                    payload,
                    user,
                };
            }
        } else if (isPasskeyResponse(payload)) {
            const user: JWTUser | undefined = await this.verifyFIDO(payload, req, res);
            if (user) {
                return {
                    data,
                    method: this.name,
                    payload,
                    user,
                };
            }
        } else if (payload.id && payload.password) {
            const user: JWTUser | undefined = await this.verifyBasic(req, res);
            if (user) {
                return {
                    data,
                    method: this.name,
                    payload,
                    user,
                };
            }
        } else if (payload.id && payload.methodId) {
            await this.challenge(payload, req, res);
            return undefined;
        }

        if (required) {
            throw new Error("Invalid authentication request.");
        }

        return undefined;
    }

    public authenticateSync(req: HttpRequest, res: HttpResponse, required?: boolean): AuthResult | undefined {
        throw new Error("Not supported. This auth strategy must be used asynchronously.");
    }

    protected async challenge(payload: any, req: HttpRequest, res: HttpResponse): Promise<void> {
        if (!req.session) {
            throw new Error(
                "MFAStrategy requires session support. Configure the `session` config block so the " +
                    "session middleware is registered.",
            );
        }

        // Phase 2 may only be invoked immediately following a successful phase-1 (password) verification
        // for the same claimed identity — otherwise an attacker could trigger/consume a 2FA challenge for
        // any account by supplying an arbitrary `id` and a `methodId` they control (e.g. their own verified
        // contact), without ever needing that account's password.
        if (!req.session.userUid || req.session.userUid !== payload.id) {
            throw new Error("Invalid authentication request.");
        }

        // Rate limit challenge issuance itself, not just phase-1/3 credential verification — otherwise an
        // attacker who already knows the account's password could repeatedly trigger this phase to spam a
        // victim's contact with OTP notifications at no cost.
        if (this.options.checkRateLimit) {
            await this.options.checkRateLimit(payload.id, req);
        }

        const method: MFAMethod | undefined = await this.options.getMethod(payload.methodId, req.session.userUid);
        if (!method) {
            throw new Error("Invalid secondary authentication method.");
        }

        switch (method.type) {
            case MFAMethodType.FIDO2:
                {
                    if (!this.options.fidoConfig) {
                        throw new Error("No configuration exists for MFA method: FIDO2");
                    }
                    // Scope the challenge to only the specific credential the client selected — this
                    // also means an authenticator holding a different (unselected) registered
                    // credential for the same user will be refused by the client itself.
                    const credential = method.data as StoredPasskeyCredential;
                    const result = await generatePasskeyChallenge(this.options.fidoConfig, req, [
                        { id: credential.id, transports: credential.transports },
                    ]);
                    // Recorded so phase 3 can confirm the submitted assertion is for this same
                    // credential, not some other one belonging to the same user.
                    req.session.mfaMethodId = method.id;
                    res.status(200);
                    res.json(result);
                }
                break;
            case MFAMethodType.OTP:
                {
                    // Clear any stale `mfaMethodId` left over from a previous TOTP/FIDO2 challenge
                    // selection in this session — otherwise authenticate()'s routing check would
                    // misroute this OTP submission into verifyTOTP(), which always fails.
                    delete req.session.mfaMethodId;
                    const totp: string = await generateOTP(req, payload);
                    await this.options.notifyContact(method.data, totp);
                    res.status(200);
                    res.json({});
                }
                break;
            case MFAMethodType.TOTP:
                {
                    // No challenge or notification is needed — the client's authenticator app already
                    // has the current code. Record which secret was selected so phase 3 knows which
                    // one to verify the submitted code against, and so a `{id, token}` submission can
                    // be routed to TOTP verification instead of OTP (both share the same shape).
                    req.session.mfaMethodId = method.id;
                    res.status(200);
                    res.json({});
                }
                break;
            default:
                throw new Error("Unsupported MFA method: " + method.type);
        }
    }

    protected async verifyBasic(req: HttpRequest, res: HttpResponse): Promise<JWTUser | undefined> {
        const requestData: any = getBasicData(req);

        if (!requestData || !requestData.id || !requestData.password) {
            throw new Error("Invalid user id or password.");
        }

        if (this.options.checkRateLimit) {
            await this.options.checkRateLimit(requestData.id, req);
        }

        // Verify the id and password
        const user: JWTUser | undefined = await this.options.verify(requestData.id, requestData.password);
        if (user) {
            // Bind subsequent phases to this verified identity so phase 2/3 can't be invoked cold, or for a
            // different identity than the one that just passed password verification.
            if (req.session) {
                req.session.userUid = user.uid;
            }

            // Now retrieve the user's list of available 2FA methods
            const methods: MFAMethod[] = await this.options.getMethods(user.uid);
            if (methods.length > 0) {
                // Send the list of 2FA methods back to the client to select from. `uid` is included
                // because phase 2/3 require it as the request's `id` — the internal uid, not
                // whatever login identifier (email, alias, etc.) the client used for phase 1 — and
                // this is the only point at which the client ever learns it.
                res.status(200);
                res.json({ uid: user.uid, methods });
                return undefined;
            } else if (this.options.require2FA) {
                throw new Error("No secondary authentication methods available.");
            }

            return user;
        } else {
            throw new Error("Invalid user id or password.");
        }
    }

    protected async verifyFIDO(payload: any, req: HttpRequest, res: HttpResponse): Promise<JWTUser | undefined> {
        if (!req.session) {
            throw new Error(
                "MFAStrategy requires session support. Configure the `session` config block so the " +
                    "session middleware is registered.",
            );
        }

        // The phase-1-verified identity, phase-2-selected credential, and challenge are all
        // single-use — cleared once phase 3 completes, regardless of outcome, mirroring verifyOTP().
        const userUid: string | undefined = req.session.userUid;
        const methodId: string | undefined = req.session.mfaMethodId;
        const expectedChallenge: string | undefined = req.session.challenge;
        delete req.session.userUid;
        delete req.session.mfaMethodId;
        delete req.session.challenge;

        // Rate limited by the phase-1-verified identity rather than `payload.id` — unlike OTP/TOTP,
        // a FIDO2 assertion's `id` is the credential id, not something an attacker-controlled value
        // can be reasonably bucketed on.
        if (this.options.checkRateLimit && userUid) {
            await this.options.checkRateLimit(userUid, req);
        }

        if (!userUid || !methodId || !expectedChallenge || !isPasskeyResponse(payload)) {
            return undefined;
        }
        if (!this.options.fidoConfig) {
            throw new Error("No configuration exists for MFA method: FIDO2");
        }

        const credential: StoredPasskeyCredential | undefined = await this.options.getCredentialById(payload.id);
        // Only the specific credential selected during phase 2, and only if it belongs to the
        // phase-1-verified identity, may complete this challenge.
        if (!credential || credential.id !== methodId || credential.uid !== userUid) {
            return undefined;
        }

        const result = await verifyPasskeyChallenge(credential, this.options.fidoConfig, expectedChallenge, payload);
        if (!result.verified) {
            return undefined;
        }

        // Counter regression check — see PasskeyStrategy/FIDO2Strategy for the same guard against
        // cloned authenticators.
        const newCounter: number = result.authenticationInfo.newCounter;
        if (newCounter !== 0 && newCounter <= credential.counter) {
            return undefined;
        }
        await this.options.updateCredentialCounter(credential.id, newCounter);

        return await this.options.getUser(userUid);
    }

    protected async verifyOTP(payload: any, req: HttpRequest, res: HttpResponse): Promise<JWTUser | undefined> {
        if (this.options.checkRateLimit) {
            await this.options.checkRateLimit(payload.id, req);
        }

        const valid: boolean = await verifyOTP(req, payload);

        // The phase-1-verified identity is single-use — cleared once phase 3 completes, regardless of outcome.
        const userUid: string | undefined = req.session?.userUid;
        delete req.session?.userUid;

        if (!valid || !userUid) {
            return undefined;
        }
        // Resolve the user from the session-bound identity established in verifyBasic(), not from the
        // client-supplied `payload.id`, which must never be trusted to select which account gets authenticated.
        return await this.options.getUser(userUid);
    }

    protected async verifyTOTP(payload: any, req: HttpRequest, res: HttpResponse): Promise<JWTUser | undefined> {
        if (this.options.checkRateLimit) {
            await this.options.checkRateLimit(payload.id, req);
        }

        // The phase-1-verified identity and the phase-2-selected secret are both single-use —
        // cleared once phase 3 completes, regardless of outcome, mirroring verifyOTP().
        const userUid: string | undefined = req.session?.userUid;
        const methodId: string | undefined = req.session?.mfaMethodId;
        delete req.session?.userUid;
        delete req.session?.mfaMethodId;

        if (!userUid || !methodId || payload.id !== userUid) {
            return undefined;
        }

        // Re-fetch the specific secret selected during phase 2 — this also re-confirms it still
        // belongs to the phase-1-verified identity and is actually a TOTP method.
        const method: MFAMethod | undefined = await this.options.getMethod(methodId, userUid);
        if (!method || method.type !== MFAMethodType.TOTP) {
            return undefined;
        }

        const result: any = await verifyTOTP(payload.token, method.data);
        if (!result || !result.valid) {
            return undefined;
        }

        if (this.options.updateSecretTimeStep) {
            await this.options.updateSecretTimeStep(methodId, result.timeStep);
        }

        return await this.options.getUser(userUid);
    }
}
