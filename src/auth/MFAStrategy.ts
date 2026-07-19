////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import type { JWTUser } from "@rapidrest/core";
import { AuthStrategy, HttpRequest, HttpResponse, AuthResult } from "@rapidrest/service-core";
import { OTPContact, PasskeyConfig } from "./types.js";
import {
    generateOTP,
    generatePasskeyChallenge,
    getBasicData,
    getRequestData,
    isOTPResponse,
    isPasskeyResponse,
    verifyOTP,
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
     * Retrieves the user's secondary authentication method for a given id.
     * NOTE: You must override this function when using this strategy.
     * @param id The unique id of the secondary auth method to retrieve.
     */
    public getMethod(id: string): Promise<MFAMethod | undefined> {
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
 * server returns with a list of available secondary authentication methods.
 * 2. Challenge - The client requests a selected 2FA challenge. If a `TOTP` 2FA method is chosen, the request is
 * processed as phase 3. For all others, a challenge is generated and stored in the session. If `OTP` is selected,
 * a notification containing the challenge token is sent to the selected verified contact.
 * 3. Verify - The client submits the completed 2FA challenge. The challenge is verified against the one stored in the
 * session, and the associated user is resolved using the `getUser()` callback.
 *
 * @author Jean-Philippe Steinmetz <rapidrests@gmail.com>
 */
export class MFAStrategy implements AuthStrategy {
    public readonly name: string = "otp";
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
            const user: JWTUser | undefined = await this.verifyOTP(payload, req, res);
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

        const method: MFAMethod | undefined = await this.options.getMethod(payload.methodId);
        if (!method) {
            throw new Error("Invalid secondary authentication method.");
        }

        switch (method.type) {
            case MFAMethodType.FIDO2:
                {
                    if (!this.options.fidoConfig) {
                        throw new Error("No configuration exists for MFA method: FIDO2");
                    }
                    const result = await generatePasskeyChallenge(this.options.fidoConfig, req);
                    res.json(result);
                }
                break;
            case MFAMethodType.OTP:
                {
                    const totp: string = await generateOTP(req, payload);
                    await this.options.notifyContact(method.data, totp);
                }
                break;
            default:
                throw new Error("Unsupported MFA method: " + method.type);
        }

        // Store the method ID used in the session
        req.session.methodId = method.id;
        res.status(200);
    }

    protected async verifyBasic(req: HttpRequest, res: HttpResponse): Promise<JWTUser | undefined> {
        const requestData: any = getBasicData(req);

        if (!requestData || !requestData.id || !requestData.password) {
            throw new Error("Invalid user id or password.");
        }

        // Verify the id and password
        const user: JWTUser | undefined = await this.options.verify(requestData.id, requestData.password);
        if (user) {
            // Now retrieve the user's list of available 2FA methods
            const methods: MFAMethod[] = await this.options.getMethods(user.uid);
            if (methods.length > 0) {
                // Send the list of 2FA methods back to the client to select from
                res.status(200);
                res.json(methods);
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
        throw new Error("Not implemented");
    }

    protected async verifyOTP(payload: any, req: HttpRequest, res: HttpResponse): Promise<JWTUser | undefined> {
        if (!(await verifyOTP(req, payload))) {
            return undefined;
        }
        return await this.options.getUser(payload.id);
    }

    protected async verifyTOTP(payload: any, req: HttpRequest, res: HttpResponse): Promise<JWTUser | undefined> {
        throw new Error("Not implemented");
    }
}
