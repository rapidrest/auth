import { JWTUser } from "@rapidrest/core";
import { BaseEntity } from "@rapidrest/service-core";

/**
 * @author Jean-Philippe Steinmetz
 */
export class AuthResult {
    public readonly refresh: string;
    public readonly token: string;
    public readonly user: JWTUser;

    constructor(other: any) {
        this.refresh = other.refresh;
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
    RECOVERY_CODES = "recovery-codes",
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
 * * `recovery-codes`
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
     * A short textual description that gives the user a hint about what the secret is.
     */
    hint?: string;

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
 * The kind of OAuth 2.0 client a `Client` record describes, per RFC 6749 §2.1.
 */
export enum ClientType {
    /** A client capable of maintaining the confidentiality of its credentials (e.g. a server-side app). */
    CONFIDENTIAL = "confidential",
    /** A client incapable of maintaining confidentiality (e.g. a native mobile app or SPA) — never issued a secret. */
    PUBLIC = "public",
}

/**
 * The method a `Client` uses to authenticate itself to the token endpoint, per RFC 6749 §2.3 and RFC 7591 §2.
 */
export enum TokenEndpointAuthMethod {
    /** `client_id`/`client_secret` sent via HTTP Basic auth (RFC 6749 §2.3.1). */
    CLIENT_SECRET_BASIC = "client_secret_basic",
    /** `client_id`/`client_secret` sent as request body parameters. */
    CLIENT_SECRET_POST = "client_secret_post",
    /** A signed JWT assertion (RFC 7523) — not yet supported by `ClientAuthUtils`. */
    PRIVATE_KEY_JWT = "private_key_jwt",
    /** No client authentication — required for a `PUBLIC` client relying on PKCE alone. */
    NONE = "none",
}

/**
 * Defines a single OAuth 2.0 / OpenID Connect client application registered with this authorization server.
 *
 * @author Jean-Philippe Steinmetz
 */
export interface Client extends BaseEntity {
    /** The opaque public identifier of the client. */
    clientId: string;

    /** The Argon2id hash of the client's secret. Unset for a `PUBLIC` client. */
    clientSecretHash?: string;

    /** Whether this client can maintain the confidentiality of its credentials. */
    clientType: ClientType;

    /** A human-readable name for the client, shown on a consent screen. */
    clientName: string;

    /** The exact-match allow-list of redirect URIs this client may request tokens be delivered to. */
    redirectUris: string[];

    /** The OAuth grant types this client is permitted to use (e.g. `authorization_code`, `refresh_token`). */
    grantTypes: string[];

    /** The OAuth response types this client is permitted to request (e.g. `code`). */
    responseTypes: string[];

    /** The space-delimited set of scopes this client may request. */
    scope: string;

    /** How this client authenticates itself to the token endpoint. */
    tokenEndpointAuthMethod: TokenEndpointAuthMethod;

    /** Whether PKCE is required for this client. Always `true` for a `PUBLIC` client, regardless of what was requested at registration. */
    requirePkce: boolean;

    /** The URI to fetch this client's JWK set from, for future `private_key_jwt` support. */
    jwksUri?: string;

    /** This client's JWK set inline, as an alternative to `jwksUri`. */
    jwks?: any;

    /** Contact addresses for the people/team responsible for this client (RFC 7591 `contacts`). */
    contacts?: string[];

    /** A URI to the client's logo, shown on a consent screen. */
    logoUri?: string;

    /** A URI to the client's home page. */
    clientUri?: string;

    /** A URI to the client's terms of service. */
    tosUri?: string;

    /** A URI to the client's privacy policy. */
    policyUri?: string;

    /** An identifier for the client software, shared across every instance of it (RFC 7591 `software_id`). */
    softwareId?: string;

    /** The version of the client software. */
    softwareVersion?: string;

    /** The `uid` of the `User` who registered this client, if registered by an authenticated user. */
    ownerUid?: string;

    /**
     * Set to `true` to skip the consent screen for this client. Only ever set by a downstream admin path —
     * never settable via dynamic client registration, which always registers a third-party client.
     */
    firstParty: boolean;

    /** The Argon2id hash of this client's RFC 7592 registration access token, used to manage its own registration. */
    registrationAccessTokenHash?: string;

    /** Set to `true` to reject every authorization/token request for this client. */
    disabled?: boolean;
}

/** The lifecycle status of a `SigningKey`. */
export enum SigningKeyStatus {
    /** Currently used to sign new tokens. Exactly one key is active at a time. */
    ACTIVE = "active",
    /** No longer used to sign new tokens, but still served from the JWKS endpoint so already-issued,
     * not-yet-expired tokens can still be verified. */
    RETIRED = "retired",
}

/**
 * Defines a single asymmetric key pair used to sign tokens issued by this authorization server.
 *
 * @author Jean-Philippe Steinmetz
 */
export interface SigningKey extends BaseEntity {
    /** The key id, embedded in every token's `kid` header so a verifier can select the matching public key. */
    kid: string;

    /** The signing algorithm this key is used with. */
    alg: "RS256";

    /** The public half of the key pair, as a JWK — safe to serve directly from `/jwks.json`. */
    publicKeyJwk: any;

    /** The private half of the key pair, PEM-encoded and encrypted at rest (see `SigningKeyUtils`). */
    privateKeyEncrypted: string;

    /** Whether this key is currently used to sign new tokens, or only retained to verify old ones. */
    status: SigningKeyStatus;

    /** The date this key became `ACTIVE`. */
    activatedAt: Date;

    /** The date this key was retired, if it has been. */
    retiredAt?: Date;
}

/**
 * Defines a single, one-time-use OAuth 2.0 authorization code (RFC 6749 §4.1.2), issued by
 * `BaseOAuthAuthorizeRoute` and redeemed by `BaseOAuthTokenRoute`'s `authorization_code` grant.
 *
 * @author Jean-Philippe Steinmetz
 */
export interface AuthorizationCode extends BaseEntity {
    /** The SHA-256 hex digest of the opaque code. The raw code itself is never persisted. */
    codeHash: string;

    /** The `clientId` of the `Client` this code was issued to. */
    clientId: string;

    /** The `uid` of the `User` (resource owner) who authorized this code. */
    userUid: string;

    /** The exact `redirect_uri` presented at `/authorize` — must match exactly again at `/token`. */
    redirectUri: string;

    /** The space-delimited set of scopes granted. */
    scope: string;

    /** The RFC 7636 PKCE code challenge, if the client used PKCE. */
    codeChallenge?: string;

    /** The method used to derive `codeChallenge` from the client's `code_verifier`. */
    codeChallengeMethod?: "S256" | "plain";

    /** The OIDC `nonce` to carry into the `id_token`, if the client requested the `openid` scope. */
    nonce?: string;

    /** When this code expires — typically ~60 seconds after issuance. */
    expiresAt: Date;

    /**
     * Set to `true` once this code has been redeemed at `/token`. A second presentation of an
     * already-used code is treated as a replay/leak: see `BaseOAuthTokenRoute`.
     */
    used: boolean;
}

/**
 * Records a resource owner's consent for a `Client` to be granted a set of scopes, so a returning user
 * isn't re-prompted for consent they've already given. Not created for a `Client` with `firstParty: true`,
 * which skips consent entirely.
 *
 * @author Jean-Philippe Steinmetz
 */
export interface ConsentGrant extends BaseEntity {
    /** The `uid` of the `User` who granted consent. */
    userUid: string;

    /** The `clientId` of the `Client` consent was granted to. */
    clientId: string;

    /** The space-delimited, cumulative set of scopes approved across every consent decision so far. */
    scope: string;

    /** When consent was first granted. */
    grantedAt: Date;

    /** When this grant was last relied upon to skip the consent screen. */
    lastUsedAt?: Date;
}

/**
 * Defines a single OAuth 2.0 refresh token (RFC 6749 §1.5), issued alongside an access token whenever the
 * client's `grantTypes` includes `refresh_token`, and redeemed by `BaseOAuthTokenRoute`'s `refresh_token`
 * grant to obtain a new access token without the resource owner re-authenticating.
 *
 * @author Jean-Philippe Steinmetz
 */
export interface OAuthRefreshToken extends BaseEntity {
    /** The SHA-256 hex digest of the opaque token. The raw token itself is never persisted. */
    tokenHash: string;

    /** The `clientId` of the `Client` this token was issued to. */
    clientId: string;

    /** The `uid` of the `User` (resource owner) this token acts on behalf of. Absent for a token issued via
     * the `client_credentials` grant, which has no resource owner. */
    userUid?: string;

    /** The space-delimited set of scopes this token (and any it rotates into) is authorized for. */
    scope: string;

    /**
     * Groups every token produced by rotating a single original refresh token into one lineage. A brand new
     * grant starts a fresh `familyId`; each rotation carries the same `familyId` forward. Presenting a token
     * whose `revoked` is already `true` — a replayed, already-rotated-out token — revokes every token sharing
     * its `familyId`, per RFC 9700 §4.14.2.
     */
    familyId: string;

    /** When this token expires. */
    expiresAt: Date;

    /** Set to `true` once this token has either been rotated (see `replacedByHash`) or explicitly revoked. */
    revoked: boolean;

    /** When this token was revoked, if it has been. */
    revokedAt?: Date;

    /** The `tokenHash` of the token that replaced this one via rotation, for audit — distinguishes a
     * routine rotation from an explicit revocation. */
    replacedByHash?: string;
}

/**
 * Defines a single user's account within the system.
 *
 * @author Jean-Philippe Steinmetz
 */
export interface User extends BaseEntity, JWTUser {
    /**
     * Set to `true` to require multi-factor authentication for this account, otherwise set to `false`.
     *
     * Default value is set by `@Config("auth:require_mfa")`.
     */
    requireMFA?: boolean;

    /**
     * The epoch-millisecond timestamp (see `Date.now()`) at which every refresh token issued for this account
     * before that moment was revoked (see `BaseAccountRoute.revokeSessions()`/`BaseAuthRefreshRoute`). A
     * refresh token whose `iat` claim predates this is rejected. Does not affect already-issued *access*
     * tokens, which remain valid until their own natural (short) expiry regardless — see
     * `revokeSessions()`'s doc comment for why that's an inherent limitation, not an oversight.
     */
    sessionsRevokedAt?: number;
}
