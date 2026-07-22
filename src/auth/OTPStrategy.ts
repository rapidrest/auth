////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import type { JWTUser } from "@rapidrest/core";
import { AuthStrategy, HttpRequest, HttpResponse, AuthResult } from "@rapidrest/service-core";
import { generateOTP, getRequestData, obfuscateContact, verifyOTP } from "./shared.js";
import { OTPContact } from "./types.js";

/**
 * Describes the configuration options that can be used to initialize OTPStrategy.
 *
 * @author Jean-Philippe Steinmetz
 */
export class OTPStrategyOptions {
    /**
     * Set to `true` to enable discovery of a user's aliases. Default is `false`.
     *
     * Be careful enabling this as it can be used as a way for an attacker to discover sensitive information.
     */
    public allowDiscovery?: boolean;
    /** The name of the header to look for when performing header based authentication. Default value is `Authorization`. */
    public headerKey: string = "authorization";
    /** The authorization scheme type when using header based authentication. Default value is `otp`. */
    public headerScheme: string = "otp";
    /**
     * Optional hook invoked with the claimed identifier before a new OTP is generated/sent (phase 2), and
     * again before the submitted token is verified (phase 3). Implementations should throw to reject the
     * request once a caller-defined attempt threshold has been exceeded (see `RateLimiter`). A no-op when not
     * provided.
     */
    public checkRateLimit?(identifier: string, req: HttpRequest): Promise<void>;
    /**
     * Retrieves the user's contact information for a given id.
     * NOTE: You must override this function when using this strategy.
     * @param id The unique id of the contact to retrieve.
     */
    public getContact(id: string): Promise<OTPContact | undefined> {
        throw new Error("Did you forget to override OTPStrategyOptions.getContact?");
    }
    /**
     * Retrieves the list of available contacts for the user with the given id.
     * NOTE: You must override this function when using this strategy.
     * @param id The unique id of the user.
     */
    public getContacts(id: string): Promise<OTPContact[]> {
        throw new Error("Did you forget to override OTPStrategyOptions.getContacts?");
    }
    /**
     * Retrieves the user data for the given unique identifier after authentication has completed successfully.
     * NOTE: You must override this function when using this strategy.
     * @param id The unique identifier of the user that has been successfully authenticated.
     */
    public getUser(uid: string): Promise<JWTUser | undefined> {
        throw new Error("Did you forget to override OTPStrategyOptions.getUsers?");
    }
    /**
     * Sends a notification to the specified contact with the provided OTP token.
     * NOTE: You must override this function when using this strategy.
     * @param contact The contact to send the OTP token to.
     * @param token The OTP token to send to the user.
     */
    public notifyContact(contact: OTPContact, token: string): Promise<void> {
        throw new Error("Did you forget to override OTPStrategyOptions.notify?");
    }
}

/**
 * Implements an strategy for authenticating a user with a One Time Password (OTP) that is sent to one of the user's
 * verified contact methods. This allows for implementation of a password-less login flow. This strategy requires that
 * an existing user account has already been registered with at least one verified contact method.
 *
 * This strategy should not to be confused with Time-Based One Time Password (TOTP) authentication which uses a
 * pre-shared security key, often stored on the user's device (e.g. authenticator app) or digital vault (e.g. 1Password,
 * Bitwarden, etc.). For TOTP authentication, see `TOTPStrategy`.
 *
 * The login flow has three phases:
 *
 * 1. Discovery - The client requests a list of contacts for a given user id. The `getContacts()` callback is used to
 * return the list of contacts.
 * 2. Challenge - The client requests a OTP token to be sent to the contact with a specified id. The
 * OTP token is generated and sent to the contact using the `notify()` callback and stored in the session.
 * 3. Verify - The client submits the OTP token and contact id. The OTP token is verified against the one stored in the
 * session, and the associated user is resolved using the `getUser()` callback.
 *
 * The client sends request data either in the `Authorization` header or the request body in standard form-data format
 * (e.g. `id=<id>&token=<otp>`). For example, the initial challenge request (step 2) can be sent as
 * `Authorization: otp id=<contact_id>`. The final verification request (step 3) is then sent as
 * `Authorization: otp id=<contact_id>&token=<otp>`.
 *
 * WARNING: Allowing discovery (setting `OTPStrategyOptions.allowDiscovery` to `true`) is a potential side-channel
 * attack allowing anyone to discover or gather partial contact information about a given user. For improved security,
 * the returned list of contacts is partially obfuscated. However, enough information is still provided that an
 * attacker may be able to harvest information anyway. For example, a phone number will be obfuscated from
 * `818-867-5309` to `****5309`. An email address will be obfuscated from `john.smith@gmail.com` to
 * `j****th@gmail.com`.
 *
 * @author Jean-Philippe Steinmetz <rapidrests@gmail.com>
 */
export class OTPStrategy implements AuthStrategy {
    public readonly name: string = "otp";
    private options: OTPStrategyOptions;
    private regexHeaderScheme: RegExp;

    constructor(options: OTPStrategyOptions) {
        this.options = options;
        this.regexHeaderScheme = new RegExp("^" + this.options.headerScheme + "$", "i");
    }

    public async authenticate(
        req: HttpRequest,
        res: HttpResponse,
        required?: boolean,
    ): Promise<AuthResult | undefined> {
        const { data, payload } = getRequestData(req, this.options.headerKey, this.options.headerScheme);

        if (payload.id && payload.token) {
            const user: JWTUser | undefined = await this.verify(payload, req, res);
            if (user) {
                return {
                    data,
                    method: this.name,
                    payload,
                    user,
                };
            }
        } else if (payload.id) {
            return await this.challenge(payload, req, res);
        } else if (this.options.allowDiscovery) {
            return await this.discovery(req, res);
        }

        if (required) {
            throw new Error("Invalid authentication request.");
        }

        return undefined;
    }

    public authenticateSync(req: HttpRequest, res: HttpResponse, required?: boolean): AuthResult | undefined {
        throw new Error("Not supported. This auth strategy must be used asynchronously.");
    }

    protected async discovery(req: HttpRequest, res: HttpResponse): Promise<any> {
        const id: string | undefined = (req.query?.id as string) ?? undefined;
        if (id && this.options.checkRateLimit) {
            await this.options.checkRateLimit(id, req);
        }

        let contacts: OTPContact[] = (await this.options.getContacts(id)) ?? [];
        contacts = contacts.map((c) => ({ contact: obfuscateContact(c.contact, c.type), type: c.type }));
        res.status(200);
        res.json(contacts);
        return undefined;
    }

    protected async challenge(payload: any, req: HttpRequest, res: HttpResponse): Promise<any> {
        if (!req.session) {
            throw new Error(
                "OTPStrategy requires session support. Configure the `session` config " +
                    "block so the session middleware is registered.",
            );
        }

        if (this.options.checkRateLimit) {
            await this.options.checkRateLimit(payload.id, req);
        }

        const contact: OTPContact | undefined = await this.options.getContact(payload.id);
        if (!contact) {
            return undefined;
        }

        const token: string = await generateOTP(req, payload);
        await this.options.notifyContact(contact, token);

        res.status(200);
        res.json({});
        return undefined;
    }

    protected async verify(payload: any, req: HttpRequest, res: HttpResponse): Promise<JWTUser | undefined> {
        if (this.options.checkRateLimit) {
            await this.options.checkRateLimit(payload.id, req);
        }
        if (!(await verifyOTP(req, payload))) {
            return undefined;
        }
        return this.options.getUser(payload.id);
    }
}
