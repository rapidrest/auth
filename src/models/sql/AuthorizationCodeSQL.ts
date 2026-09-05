///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { BaseEntity, DocDecorators, ModelDecorators, PersistenceDecorators } from "@rapidrest/service-core";
import { ObjectDecorators } from "@rapidrest/core";
import { AuthorizationCode } from "../types.js";

const { Description } = DocDecorators;
const { DataStore, Identifier, Protect } = ModelDecorators;
const { Nullable } = ObjectDecorators;
const { Column, Entity, Index } = PersistenceDecorators;

/**
 * Implementation of the `AuthorizationCode` interface for storage in a SQL database. If MongoDB is desired,
 * please use `models.mongo.AuthorizationCodeMongo` instead.
 *
 * @author Jean-Philippe Steinmetz
 */
@DataStore("sql")
@Entity()
@Description("Defines a single, one-time-use OAuth 2.0 authorization code.")
@Protect(
    {
        uid: "AuthorizationCode",
        records: [
            {
                userOrRoleId: "anonymous",
                actions: [],
            },
            {
                userOrRoleId: ".*",
                actions: [],
            },
        ],
    },
    true,
)
export class AuthorizationCodeSQL extends BaseEntity implements AuthorizationCode {
    @Column()
    @Identifier
    @Index("codeHash", { unique: true })
    public codeHash: string = "";

    @Column()
    @Index("authcode_clientId")
    public clientId: string = "";

    @Column()
    @Index("authcode_userUid")
    public userUid: string = "";

    @Column()
    public redirectUri: string = "";

    @Column()
    public scope: string = "";

    @Column({ nullable: true })
    @Nullable
    public codeChallenge?: string;

    @Column({ type: "varchar", nullable: true })
    @Nullable
    public codeChallengeMethod?: "S256" | "plain";

    @Column({ nullable: true })
    @Nullable
    public nonce?: string;

    @Column()
    public expiresAt: Date = new Date();

    @Column()
    public used: boolean = false;

    constructor(other?: Partial<AuthorizationCodeSQL>) {
        super(other);

        if (other) {
            this.codeHash = other.codeHash !== undefined ? other.codeHash : this.codeHash;
            this.clientId = other.clientId !== undefined ? other.clientId : this.clientId;
            this.userUid = other.userUid !== undefined ? other.userUid : this.userUid;
            this.redirectUri = other.redirectUri !== undefined ? other.redirectUri : this.redirectUri;
            this.scope = other.scope !== undefined ? other.scope : this.scope;
            this.codeChallenge = other.codeChallenge !== undefined ? other.codeChallenge : this.codeChallenge;
            this.codeChallengeMethod =
                other.codeChallengeMethod !== undefined ? other.codeChallengeMethod : this.codeChallengeMethod;
            this.nonce = other.nonce !== undefined ? other.nonce : this.nonce;
            this.expiresAt = other.expiresAt !== undefined ? other.expiresAt : this.expiresAt;
            this.used = other.used !== undefined ? other.used : this.used;
        }
    }
}
