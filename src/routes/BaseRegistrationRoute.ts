////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import { ApiError, JWTUtils, MessagingUtils, ObjectDecorators, ValidationUtils } from "@rapidrest/core";
import {
    ApiErrors,
    DocDecorators,
    HttpRequest,
    ObjectFactory,
    RepoUtils,
    RouteDecorators,
} from "@rapidrest/service-core";
import { Alias, AliasType, AuthResult, User } from "../models/types.js";
import { generateOTP, verifyOTP } from "../auth/shared.js";

const { Config, Init, Inject, Logger } = ObjectDecorators;
const { Summary, Description } = DocDecorators;
const { Post, Request } = RouteDecorators;

interface StartBody {
    email?: string;
    phone?: string;
}

interface VerifyBody {
    email?: string;
    phone?: string;
    token?: string;
}

/**
 * Provides a simple account registration flow that verifies an e-mail or phone number using OTP authentication before
 * creating the account.
 *
 * The registration flow:
 * 1. Client calls `POST /start` with either an e-mail address of phone number to verify.
 * 2. Sends an OTP code to the provided email or phone number in step 1.
 * 3. Client calls `POST /verify` with the email or phone number and OTP code.
 * 4. If OTP code is verified, creates a new `User` and `Alias`, returns a valid JWT token.
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseRegistrationRoute<U extends User, A extends Alias> {
    protected abstract aliasClass: any;
    protected abstract userClass: any;

    @Config("auth:default_scopes", [])
    protected defaultScopes: string[] = [];

    @Config("auth")
    protected jwtConfig?: any;

    @Logger
    protected logger: any;

    @Inject(MessagingUtils)
    protected messagingUtils?: MessagingUtils;

    @Inject(ObjectFactory)
    protected objectFactory?: ObjectFactory;

    protected aliasRepo?: RepoUtils<A>;
    protected userRepo?: RepoUtils<U>;

    @Init
    protected async initialize(): Promise<void> {
        if (!this.objectFactory) {
            throw new Error("objectFactory is not set.");
        }

        if (!this.aliasRepo && this.aliasClass) {
            this.aliasRepo = await this.objectFactory.newInstance(RepoUtils, {
                name: this.aliasClass.name,
                args: [this.aliasClass],
            });
        }

        if (!this.userRepo && this.userClass) {
            this.userRepo = await this.objectFactory.newInstance(RepoUtils, {
                name: this.userClass.name,
                args: [this.userClass],
            });
        }
    }

    /**
     * Sends a one-time verification code to the provided e-mail address or phone number.
     */
    @Summary("Begin account registration")
    @Description("Sends a one-time verification code to the provided e-mail address or phone number.")
    @Post("/start")
    public async start(body: StartBody, @Request req: HttpRequest): Promise<Record<string, never>> {
        if (!this.aliasRepo) {
            throw new Error("aliasRepo is not set.");
        }
        if (!req.session) {
            throw new Error("Registration requires session support. Configure the `session` config block.");
        }

        const email = (body?.email ?? "").trim().toLowerCase();
        const phone = (body?.phone ?? "").trim();
        try {
            if (email) {
                ValidationUtils.checkEmail(email);
            }
            if (phone) {
                ValidationUtils.checkPhone(phone);
            }
        } catch (err) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "A valid e-mail address or phone number is required.");
        }

        if (email) {
            const existing = await this.aliasRepo.find({ alias: email, type: AliasType.EMAIL }, { ignoreACL: true });
            if (existing.some((a) => a.verified)) {
                // An account for this identifier already exists. We do not throw an error here so that this cannot
                // be used to discover registered accounts.
                return {};
            }

            const token = await generateOTP(req, { id: email });
            this.messagingUtils?.sendEmail("register-otp", { totp: token }, { to: email }).catch((err) => {
                this.logger.debug(`[BaseAuthRegisterRoute] Failed to send verification e-mail: ${err}`);
            });
            if (process.env.environment !== "production") {
                this.logger.debug(`[BaseAuthRegisterRoute] verification code for ${email}: ${token}`);
            }
        } else if (phone) {
            const existing = await this.aliasRepo.find({ alias: phone, type: AliasType.PHONE }, { ignoreACL: true });
            if (existing.some((a) => a.verified)) {
                // An account for this identifier already exists. We do not throw an error here so that this cannot
                // be used to discover registered accounts.
                return {};
            }

            const token = await generateOTP(req, { id: phone });
            this.messagingUtils?.sendSMS("register-otp", { totp: token }, { to: phone }).catch((err) => {
                this.logger.debug(`[BaseAuthRegisterRoute] Failed to send verification SMS: ${err}`);
            });
            if (process.env.environment !== "production") {
                this.logger.debug(`[BaseAuthRegisterRoute] verification code for ${phone}: ${token}`);
            }
        }

        return {};
    }

    /**
     * Verifies the one-time code sent by `start()`. On success, creates a new `User` and verified `Alias`
     * and returns an JWT token.
     */
    @Summary("Verify registration e-mail code")
    @Description("Verifies the one-time code sent to the claimed e-mail address so that registration can be completed.")
    @Post("/verify")
    public async verify(body: VerifyBody, @Request req: HttpRequest): Promise<AuthResult> {
        if (!this.aliasRepo) {
            throw new Error("aliasRepo is not set.");
        }
        if (!this.userRepo) {
            throw new Error("userRepo is not set.");
        }
        if (!req.session) {
            throw new Error("Registration requires session support. Configure the `session` config block.");
        }

        const email = (body?.email ?? "").trim().toLowerCase();
        const phone = (body?.phone ?? "").trim();
        const id = email || phone;
        const token = body?.token ?? "";
        if (!id || !token) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "An id and verification code are required.");
        }

        let valid: boolean;
        try {
            valid = await verifyOTP(req, { id, token });
        } catch (err) {
            valid = false;
        }
        if (!valid) {
            throw new ApiError(ApiErrors.AUTH_FAILED, 400, "The verification code is invalid or has expired.");
        }

        const user = await this.userRepo.create({ verified: true } as any, {
            ignoreACL: true,
        });
        const options = { ignoreACL: true, user };
        if (email) {
            await this.aliasRepo.create(
                { alias: email, type: AliasType.EMAIL, userUid: user.uid, verified: true } as any,
                options,
            );
        }
        if (phone) {
            await this.aliasRepo.create(
                { alias: phone, type: AliasType.PHONE, userUid: user.uid, verified: true } as any,
                options,
            );
        }

        const result = new AuthResult({
            token: await JWTUtils.createToken(this.jwtConfig, {
                ...user,
                scopes: this.defaultScopes,
            }),
            user,
        });
        return result;
    }
}
