////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { ApiError, ObjectDecorators } from "@rapidrest/core";
import { ApiErrors, ObjectFactory, RepoUtils } from "@rapidrest/service-core";
import { SystemSettings, SystemSettingsEntity } from "../models/types.js";
const { Config, Init, Logger } = ObjectDecorators;

/** The fixed `uid` that the single `SystemSettings` record is always read and written under. */
export const SYSTEM_SETTINGS_UID = "default";

/**
 * Utility class for reading and writing the `SystemSettings` at runtime.
 *
 * The settings are stored as a single record under `SYSTEM_SETTINGS_UID`. The record is created on first access,
 * seeded from the server configuration, and from then on the stored values take precedence so that an administrator
 * can change them without restarting (or reconfiguring) the server.
 *
 * Instantiate via `ObjectFactory` so that every route shares one instance per settings class, e.g.:
 * ```ts
 * await objectFactory.newInstance(SystemSettingsUtils, { name: SystemSettingsSQL.name, args: [SystemSettingsSQL] });
 * ```
 *
 * @author Jean-Philippe Steinmetz
 */
export class SystemSettingsUtils {
    @Config("auth:allowRegistration", true)
    protected allowRegistration: boolean = true;

    @Config("auth:requireMFA", false)
    protected requireMFA: boolean = false;

    @Config("auth:allowMultiplePasswords", false)
    protected allowMultiplePasswords: boolean = false;

    @Logger
    protected logger: any;

    protected repo?: RepoUtils<SystemSettingsEntity>;
    protected settingsClass: any;

    // Automatically injected by ObjectFactory on instantiation
    private _objectFactory?: ObjectFactory;

    constructor(settingsClass: any) {
        this.settingsClass = settingsClass;
    }

    @Init
    protected async init(): Promise<void> {
        if (!this._objectFactory) {
            throw new Error("objectFactory is not set.");
        }

        if (!this.repo) {
            this.repo = await this._objectFactory.newInstance(RepoUtils, {
                name: `${RepoUtils.name}:${this.settingsClass.name}`,
                args: [this.settingsClass],
            });
        }
    }

    /**
     * Returns the persisted settings record, creating it seeded from `@Config` if it doesn't exist yet. Two
     * concurrent first reads racing to create the record are tolerated: the loser re-reads the winner's record.
     */
    public async getEntity(): Promise<SystemSettingsEntity> {
        if (!this.repo) {
            throw new Error("repo is not set.");
        }

        const existing: SystemSettingsEntity | undefined = await this.repo.findOne(SYSTEM_SETTINGS_UID, {
            ignoreACL: true,
        });
        if (existing) {
            return existing;
        }

        try {
            const result = await this.repo.create(
                new this.settingsClass({
                    uid: SYSTEM_SETTINGS_UID,
                    allowRegistration: this.allowRegistration,
                    requireMFA: this.requireMFA,
                    allowMultiplePasswords: this.allowMultiplePasswords,
                }),
                { ignoreACL: true },
            );
            return result;
        } catch (err) {
            if (err instanceof ApiError && err.code === ApiErrors.IDENTIFIER_EXISTS) {
                const recovered: SystemSettingsEntity | undefined = await this.repo.findOne(SYSTEM_SETTINGS_UID, {
                    ignoreACL: true,
                });
                if (recovered) {
                    return recovered;
                }
            }
            throw err;
        }
    }

    /**
     * Returns the effective settings, falling back to `@Config` for any value that isn't stored or can't be read.
     */
    public async get(): Promise<SystemSettings> {
        let settings: SystemSettings | undefined;
        try {
            settings = await this.getEntity();
        } catch (err) {
            this.logger?.warn(`Failed to read auth settings, falling back to configuration. ${err}`);
        }

        return new SystemSettings({
            allowRegistration: settings?.allowRegistration ?? this.allowRegistration,
            requireMFA: settings?.requireMFA ?? this.requireMFA,
            allowMultiplePasswords: settings?.allowMultiplePasswords ?? this.allowMultiplePasswords,
        });
    }

    /**
     * Applies the given partial update to the persisted settings and returns the new effective settings. An
     * omitted key is left untouched. Unlike the settings this replaced (site branding's `allowRegistration`),
     * `SystemSettings` intentionally has no "revert to `@Config`" sentinel: once the record is seeded, its
     * stored values are always authoritative, so `null` (and any other non-boolean value) is rejected rather
     * than silently accepted as a way to clear a field back to configuration.
     */
    public async update(changes: Partial<SystemSettings>): Promise<SystemSettings> {
        if (!this.repo) {
            throw new Error("repo is not set.");
        }

        // Only known `SystemSettings` fields are ever merged in, both to reject a bad value (`null`/wrong type)
        // up front and so an unrelated key on the request body (e.g. `uid`, smuggled in from a client echoing
        // back a previous read) can never reach `RepoUtils.update()` and mutate the singleton row's identity.
        const picked: Partial<SystemSettings> = {};
        if ("allowRegistration" in changes) {
            if (typeof changes.allowRegistration !== "boolean") {
                throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "allowRegistration must be a boolean.");
            }
            picked.allowRegistration = changes.allowRegistration;
        }
        if ("requireMFA" in changes) {
            if (typeof changes.requireMFA !== "boolean") {
                throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "requireMFA must be a boolean.");
            }
            picked.requireMFA = changes.requireMFA;
        }
        if ("allowMultiplePasswords" in changes) {
            if (typeof changes.allowMultiplePasswords !== "boolean") {
                throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "allowMultiplePasswords must be a boolean.");
            }
            picked.allowMultiplePasswords = changes.allowMultiplePasswords;
        }

        const existing: SystemSettingsEntity = await this.getEntity();
        const merged: Partial<SystemSettings> = { ...existing, ...picked };
        const updated: SystemSettingsEntity = await this.repo.update(new this.settingsClass(merged), existing, {
            ignoreACL: true,
        });

        return new SystemSettings({
            allowRegistration: updated.allowRegistration ?? this.allowRegistration,
            requireMFA: updated?.requireMFA ?? this.requireMFA,
            allowMultiplePasswords: updated?.allowMultiplePasswords ?? this.allowMultiplePasswords,
        });
    }
}
