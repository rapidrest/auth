////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import { ObjectFactory, RepoUtils } from "@rapidrest/service-core";
import { Alias, User } from "../models/types.js";
import { ObjectDecorators } from "@rapidrest/core";
const { Init, Inject } = ObjectDecorators;

/**
 * Utility class for working with persisted `User` objects in the database.
 */
export class UserUtils<U extends User, A extends Alias> {
    protected aliasClass: any;
    protected aliasRepo?: RepoUtils<A>;
    protected userClass: any;
    protected userRepo?: RepoUtils<U>;

    @Inject(ObjectFactory)
    protected objectFactory?: ObjectFactory;

    constructor(userClass: any, aliasClass: any) {
        this.aliasClass = aliasClass;
        this.userClass = userClass;
    }

    @Init
    protected async init() {
        if (!this.objectFactory) {
            throw new Error("objectFactory is not set.");
        }

        if (!this.aliasRepo) {
            this.aliasRepo = await this.objectFactory.newInstance(RepoUtils, {
                name: `${RepoUtils.name}:${this.aliasClass.name}`,
                args: [this.aliasClass],
            });
        }

        if (!this.userRepo) {
            this.userRepo = await this.objectFactory.newInstance(RepoUtils, {
                name: `${RepoUtils.name}:${this.userClass.name}`,
                args: [this.userClass],
            });
        }
    }

    /**
     * Performs a look up of the user with the given id. The id may be one of: the user's `uid` or an `Alias`.
     *
     * @param id The unique id of the user to lookup.
     * @returns The `User` if found, otherwise `undefined`.
     */
    public async lookup(id: string): Promise<U | undefined> {
        if (!this.aliasRepo) {
            throw new Error("aliasRepo is not set.");
        }
        if (!this.userRepo) {
            throw new Error("userRepo is not set.");
        }

        // First let's try the id as the User `uid`.
        let user: U | undefined = await this.userRepo.findOne(id, { ignoreACL: true });
        if (user) {
            return user;
        }

        // Okay, now let's try looking through the user's aliases
        const aliases: A[] = await this.aliasRepo.find({ userUid: id }, { ignoreACL: true });
        user = aliases.length > 0 ? await this.userRepo.findOne(aliases[0].userUid, { ignoreACL: true }) : user;

        return user;
    }
}
