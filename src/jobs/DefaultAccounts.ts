///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
import { ObjectDecorators } from "@rapidrest/core";
import { ACLAction, BackgroundService, ObjectFactory, RepoUtils } from "@rapidrest/service-core";
import { Alias, AliasType, Contact, ContactType, Profile, Secret, SecretType, User } from "../models/types.js";
import { PasswordConfig } from "../auth/types.js";
import { generatePassword, importArgon2 } from "../auth/shared.js";
import * as path from "path";
import * as fs from "fs/promises";
import { existsSync } from "fs";

const { Config, Init, Inject, Logger } = ObjectDecorators;

export interface DefaultAccountConfig {
    name: string;
    email?: string;
    password?: string;
    phone?: string;
    roles?: string[];
}

/**
 * The `DefaultAccounts` is a single-execution background job that runs at service startup which creates
 * default user accounts for the system (e.g. the `admin` account). The default accounts to create are
 * defined in the server's `config.ts` under the key `default_accounts`.
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class DefaultAccounts<
    U extends User,
    A extends Alias,
    P extends Profile,
    S extends Secret,
> extends BackgroundService {
    protected abstract aliasClass: any;
    protected abstract profileClass: any;
    protected abstract secretClass: any;
    protected abstract userClass: any;

    protected aliasRepo?: RepoUtils<A>;

    @Config("default_accounts", [
        {
            name: "admin",
            roles: ["admin"],
        },
    ])
    protected defaultAccounts: DefaultAccountConfig[] = [];

    @Config("auth:default_scopes", [])
    protected defaultScopes: string[] = [];

    @Logger
    protected logger?: any;

    @Inject(ObjectFactory)
    protected objectFactory?: ObjectFactory;

    @Config("auth:password", new PasswordConfig())
    protected passwordConfig: PasswordConfig = new PasswordConfig();

    @Config("auth:password_file", "passwords")
    protected passwordFile?: string = "passwords";

    protected profileRepo?: RepoUtils<P>;

    protected secretRepo?: RepoUtils<S>;

    @Config("trusted_roles", ["admin"])
    protected trustedRoles: string[] = ["admin"];

    protected userRepo?: RepoUtils<U>;

    @Init
    public async init() {
        if (!this.objectFactory) {
            throw new Error("objectFactory is not set.");
        }

        if (!this.aliasRepo && this.aliasClass) {
            this.aliasRepo = await this.objectFactory.newInstance(RepoUtils, {
                name: this.aliasClass.name,
                args: [this.aliasClass],
            });
        }

        if (!this.profileRepo && this.profileClass) {
            this.profileRepo = await this.objectFactory.newInstance(RepoUtils, {
                name: this.profileClass.name,
                args: [this.profileClass],
            });
        }

        if (!this.secretRepo && this.secretClass) {
            this.secretRepo = await this.objectFactory.newInstance(RepoUtils, {
                name: this.secretClass.name,
                args: [this.secretClass],
            });
        }

        if (!this.userRepo && this.userClass) {
            this.userRepo = await this.objectFactory.newInstance(RepoUtils, {
                name: this.userClass.name,
                args: [this.userClass],
            });
        }

        // The passwords file should only exist for a short time after it was first written.
        // So if the server was restarted we remove it to prevent unauthorized access.
        if (this.passwordFile) {
            const filePath: string = path.resolve(this.passwordFile);
            if (existsSync(filePath)) {
                await fs.unlink(filePath);
            }
        }
    }

    public get schedule(): string | undefined {
        return undefined;
    }

    public run(): Promise<void> | void {
        // Do nothing
    }

    public async start(): Promise<void> {
        // Create an account in the system for each configured default
        for (const account of this.defaultAccounts) {
            // If no roles have been set for the account, apply trusted roles. If an empty set
            // was specified we do not overwrite it. We assume it was intentional.
            account.roles = account.roles !== undefined ? account.roles : this.trustedRoles;

            // First check if there is an existing account for the given name
            const aliases: A[] = (await this.aliasRepo!.find({ alias: account.name }, { ignoreACL: true })) ?? [];
            let user: U | undefined =
                aliases.length > 0 ? await this.userRepo!.findOne(aliases[0].userUid, { ignoreACL: true }) : undefined;
            if (!user) {
                // An account does not exist yet for this name. Let's create the user.
                const newUser: U = new this.userClass({ roles: account.roles, verified: true });
                user = await this.userRepo!.create(newUser, {
                    user: newUser,
                    acl: {
                        uid: newUser.uid,
                        records: [
                            {
                                userOrRoleId: newUser.uid,
                                actions: [
                                    ACLAction.COUNT,
                                    ACLAction.CREATE,
                                    ACLAction.DELETE,
                                    ACLAction.EXISTS,
                                    ACLAction.READ,
                                    ACLAction.LIST,
                                    ACLAction.TRUNCATE,
                                    ACLAction.UPDATE,
                                ],
                            },
                        ],
                    },
                });
            }

            // Now synchronize the rest of the account details. This ensures that any aliases/secrets
            // get automatically recreated to avoid lockout scenarios.
            await this.syncAccount(user, account);
        }
    }

    public stop(): Promise<void> | void {
        // Do nothing
    }

    private async syncAccount(user: User, account: DefaultAccountConfig) {
        // Create a profile for the user if one does not already exist
        let profile: P | undefined = await this.profileRepo!.findOne(user.uid, { ignoreACL: true, user });
        if (!profile) {
            profile = await this.profileRepo!.create(
                new this.profileClass({
                    uid: user.uid,
                    contacts: [],
                    givenName: "Administrator",
                }),
                {
                    user,
                },
            );
        }
        // Now merge all configured contacts with the profile
        if (profile) {
            if (account.email) {
                const emails: Contact[] = profile.contacts.filter(
                    (c) => c.type === ContactType.EMAIL && c.contact === account.email!.toLowerCase(),
                );
                if (emails.length === 0) {
                    profile?.contacts.push({
                        contact: account.email.toLowerCase(),
                        type: ContactType.EMAIL,
                        verified: true,
                    });
                }
            }
            if (account.phone) {
                const phones: Contact[] = profile.contacts.filter(
                    (c) => c.type === ContactType.PHONE && c.contact === account.phone,
                );
                if (phones.length === 0) {
                    profile?.contacts.push({
                        contact: account.phone,
                        type: ContactType.PHONE,
                        verified: true,
                    });
                }
            }
            await this.profileRepo!.update(
                {
                    uid: profile.uid,
                    version: profile.version,
                    contacts: profile.contacts,
                } as any,
                profile,
                { user },
            );
        }

        // Check to see what aliases the account has. Go through each one defined in the configuration
        // and add it as an Alias if missing.
        const aliases: A[] = await this.aliasRepo!.find({ userUid: user.uid }, { ignoreACL: true, user });
        if (account.email) {
            const email: string = account.email.trim().toLowerCase();
            const emails: A[] = aliases.filter((a) => a.type === AliasType.EMAIL && a.alias === email);
            if (emails.length === 0) {
                await this.aliasRepo!.create(
                    { alias: email, type: AliasType.EMAIL, userUid: user.uid, verified: true } as any,
                    {
                        user,
                    },
                );
            }
        }
        if (account.name) {
            const name: string = account.name.trim().toLowerCase();
            const names: A[] = aliases.filter((a) => a.type === AliasType.NAME && a.alias === name);
            if (names.length === 0) {
                await this.aliasRepo!.create(
                    { alias: name, type: AliasType.NAME, userUid: user.uid, verified: true } as any,
                    {
                        user,
                    },
                );
            }
        }
        if (account.phone) {
            const phone: string = account.phone.trim();
            const phones: A[] = aliases.filter((a) => a.type === AliasType.PHONE && a.alias === phone);
            if (phones.length === 0) {
                await this.aliasRepo!.create(
                    { alias: phone, type: AliasType.PHONE, userUid: user.uid, verified: true } as any,
                    {
                        user,
                    },
                );
            }
        }

        // Make sure there's at least one password secret for the user. Don't overwrite an existing
        // password secret as it may have changed intentionally.
        let pwCreated: boolean = false;
        const passwords: S[] = await this.secretRepo!.find(
            { type: SecretType.PASSWORD, userUid: user.uid },
            { ignoreACL: true },
        );
        if (passwords.length === 0) {
            if (!account.password) {
                // Randomly generate a new password using the password requirements
                account.password = generatePassword(this.passwordConfig);
            }

            const argon = await importArgon2();
            const secret: S = new this.secretClass({
                data: await argon.hash(account.password),
                type: SecretType.PASSWORD,
                userUid: user.uid,
            });
            await this.secretRepo!.create(secret, { user });
            pwCreated = true;
        }

        if (pwCreated) {
            this.logger.info("================================================================================");
            this.logger.info("!!!IMPORTANT!!! Write down this information. It won't be shown again.");
            this.logger.info("================================================================================");
            this.logger.info("An account has been created with the following details:");
            this.logger.info("------------------------------");
            // Write the password to a secure file location for the system adminstrator to retrieve. Alternatively,
            // if `passwordFile` is not present, this gets written exactly once to the log.
            if (this.passwordFile) {
                const filePath: string = path.resolve(this.passwordFile);
                await fs.appendFile(
                    filePath,
                    `Name=${account.name},Password=${account.password},Roles=${account.roles}\n`,
                    {
                        encoding: "utf-8",
                    },
                );
                this.logger.info(`Name: ${account.name}`);
                this.logger.info(`Password: See '${filePath}'`);
                this.logger.info(`Roles: ${account.roles}`);
                this.logger.info("================================================================================");
            } else {
                this.logger.info(`Name: ${account.name}`);
                this.logger.info(`Password: '${account.password}'`);
                this.logger.info(`Roles: ${account.roles}`);
                this.logger.info("================================================================================");
            }
        }
    }
}
