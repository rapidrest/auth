///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ObjectDecorators } from "@rapidrest/core";
import { RouteDecorators, DocDecorators, RepoUtils, ObjectFactory } from "@rapidrest/service-core";
import { Alias, AliasType, Secret, SecretType, User } from "../models/types.js";
import { obfuscateContact } from "../auth/shared.js";
import { OTPContactType } from "../auth/types.js";
import { RateLimiter } from "../auth/RateLimiter.js";
import { UserUtils } from "./UserUtils.js";

const { Config, Init, Inject } = ObjectDecorators;
const { Summary, Description, Returns } = DocDecorators;
const { Get, Query } = RouteDecorators;

/** A hint about one of the caller's OTP-eligible contacts — enough to jog their memory, not enough to sign in with. */
export interface DiscoveredOtpContact {
    /** The contact, obfuscated (e.g. `j***n@example.com`, `***1234`) — never the real value. */
    contact: string;
    type: "email" | "phone";
}

/** The set of sign-in methods available for a claimed account identifier. */
export interface DiscoverResult {
    password: boolean;
    totp: boolean;
    passkey: boolean;
    fido2: boolean;
    /** Hints only — signing in via OTP still requires the caller to type the real contact themselves. */
    otp: DiscoveredOtpContact[];
}

const EMPTY_RESULT: DiscoverResult = { password: false, totp: false, passkey: false, fido2: false, otp: [] };

/**
 * Lets an anonymous caller discover which sign-in methods (password, authenticator app, passkey, security
 * key, one-time code) are configured for a claimed account identifier, so a sign-in UI can present only
 * the methods that will actually work instead of a fixed list of every method the server supports.
 *
 * Anti-enumeration discipline (mirrors `PasskeyStrategy.challenge()`'s `?uid=` hint handling): a claimed
 * identifier that doesn't resolve to any account returns the exact same `EMPTY_RESULT` shape as an account
 * that resolves but has nothing configured — never a different shape, never a 404. This is a partial
 * mitigation only (an account *with* methods configured is still distinguishable from one with none, same
 * caveat `PasskeyStrategy` documents) — rate limiting by the claimed identifier is the other half of the
 * mitigation.
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseAuthDiscoverRoute<U extends User, A extends Alias, S extends Secret> {
    protected abstract aliasClass: any;
    protected abstract secretClass: any;
    protected abstract userClass: any;

    protected aliasRepo?: RepoUtils<A>;
    protected secretRepo?: RepoUtils<S>;

    @Inject(ObjectFactory)
    protected objectFactory?: ObjectFactory;

    @Inject(RateLimiter)
    protected rateLimiter?: RateLimiter;

    protected userUtils?: UserUtils<U, A>;

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

        if (!this.secretRepo && this.secretClass) {
            this.secretRepo = await this.objectFactory.newInstance(RepoUtils, {
                name: this.secretClass.name,
                args: [this.secretClass],
            });
        }

        if (!this.userUtils && this.userClass && this.aliasClass) {
            this.userUtils = await this.objectFactory.newInstance(UserUtils, {
                name: "default",
                args: [this.userClass, this.aliasClass],
            });
        }
    }

    protected convertAliasType(type: AliasType): OTPContactType {
        switch (type) {
            case AliasType.EMAIL:
                return OTPContactType.EMAIL;
            case AliasType.PHONE:
                return OTPContactType.SMS;
            default:
                throw new Error("Unsupported type: " + type);
        }
    }

    /**
     * Returns which sign-in methods are available for the given claimed identifier (a `User` uid or any
     * `Alias` value). Always `200`, always the same response shape, regardless of whether the identifier
     * resolves to a real account.
     */
    @Summary("Discover sign-in methods")
    @Description(
        "Returns which sign-in methods (password, authenticator app, passkey, security key, one-time code) " +
            "are available for the given claimed account identifier.",
    )
    @Returns([Object])
    @Get()
    public async discover(@Query("id") id?: string): Promise<DiscoverResult> {
        if (!id) {
            return EMPTY_RESULT;
        }

        await this.rateLimiter?.checkAndIncrement(id);

        try {
            const user: U | undefined = await this.userUtils?.lookup(id);
            if (!user) {
                return EMPTY_RESULT;
            }

            const [password, totp, passkey, fido2, verifiedAliases] = await Promise.all([
                this.hasSecretType(user.uid, SecretType.PASSWORD),
                this.hasSecretType(user.uid, SecretType.TOTP),
                this.hasSecretType(user.uid, SecretType.PASSKEY),
                this.hasSecretType(user.uid, SecretType.FIDO2),
                this.aliasRepo?.find({ userUid: user.uid, verified: true }, { ignoreACL: true }) ?? Promise.resolve([]),
            ]);

            const otp: DiscoveredOtpContact[] = verifiedAliases
                .filter((a) => a.type === AliasType.EMAIL || a.type === AliasType.PHONE)
                .map((a) => ({
                    contact: obfuscateContact(a.alias, this.convertAliasType(a.type)),
                    type: a.type as "email" | "phone",
                }));

            return { password, totp, passkey, fido2, otp };
        } catch {
            // Degrade to the same equalized response on any unexpected internal error too — never let an
            // error path leak a different shape than the "nothing configured" case.
            return EMPTY_RESULT;
        }
    }

    private async hasSecretType(userUid: string, type: SecretType): Promise<boolean> {
        if (!this.secretRepo) {
            return false;
        }
        const secrets = await this.secretRepo.find({ type, userUid }, { ignoreACL: true });
        return secrets.length > 0;
    }
}
