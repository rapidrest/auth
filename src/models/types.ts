import { JWTUser } from "@rapidrest/core";
import { BaseEntity } from "@rapidrest/service-core";

/**
 * @author Jean-Philippe Steinmetz
 */
export class AuthResult {
    public readonly token: string;
    public readonly user: User;

    constructor(other: any) {
        this.token = other.token;
        this.user = other.user;
    }
}

/**
 *
 */
export enum AliasType {
    EMAIL = "email",
    NAME = "name",
    OAUTH = "oauth",
    PHONE = "phone",
}

/**
 * Defines an alternative unique identifier for a single user account.
 */
export interface Alias extends BaseEntity {
    /** The alias to uniquely identify a specific user account. */
    alias: string;

    /** The type of data that the alias represents (e.g. email, phone, name). */
    type: AliasType;

    /** The unique identifier of the user account associated with this alias. */
    userUid: string;

    /** Indicates if this alias has been verified. */
    verified: boolean;
}

export enum ContactType {
    EMAIL = "email",
    PHONE = "phone",
}

/**
 * Defines a single contact for a giiven user account. Contacts are stored in a user's
 * `Profile`.
 *
 * @author Jean-Philippe Steinmetz
 */
export interface Contact {
    /** The contact information of a specific kind (e.g. email, phone number, etc.). */
    contact: string;
    /** The type of contact information represented (e.g. email, phone). */
    type: ContactType;
    /** Indicates if the contact information has been verified. */
    verified: boolean;
}

/**
 * Defines the set of preferences for a given user account. Preferences are stored in a user's
 * `Profile`.
 *
 * @author Jean-Philippe Steinmetz
 */
export interface Preferences {
    /** The list of contact preferences for the user (e.g. 'all', 'marketing', 'system'). */
    contact: string[];
}

/**
 * Defines available contact methods and preferences for a given user. Requires the `profile` scope to read.
 *
 * Note that the `uid` must be the same `uid` as the associated `User` record.
 *
 * @author Jean-Philippe Steinmetz
 */
export interface Profile extends BaseEntity {
    /**
     * The URL or path to the user's avatar image (e.g. gravatar).
     */
    avatar?: string;

    /**
     * The user's date of birth.
     */
    birthdate?: Date;

    /**
     * The list of the user's contacts.
     */
    contacts: Contact[];

    /**
     * The user's given name (aka: first name).
     */
    givenName?: string;

    /**
     * The user's family surname (or last name).
     */
    familyName?: string;

    /**
     * The user's account preferences.
     */
    preferences: Preferences;
}

/**
 *
 */
export enum SecretType {
    FIDO2 = "fido2",
    PASSKEY = "passkey",
    PASSWORD = "password",
    TOTP = "totp",
}

/**
 * Describes a single authentication secret associated with a specific user account. A secret is used
 * to authenticate the user with the system.
 *
 * Supported types of secrets:
 * * `fido2`
 * * `openid`
 * * `password`
 * * `passkey`
 * * `totp`
 *
 * @author Jean-Philippe Steinmetz
 */
export interface Secret extends BaseEntity {
    /**
     * The data associated with the secret.
     */
    data: any;

    /**
     * The type of secret (e.g. `fido2`, `openid`, `password`, `passkey`, `totp`)
     */
    type: SecretType;

    /**
     * The unique identifier of the user account this secret is associated with.
     */
    userUid: string;
}

/**
 * Defines a single user's account within the system.
 *
 * @author Jean-Philippe Steinmetz
 */
export interface User extends BaseEntity, JWTUser {}
