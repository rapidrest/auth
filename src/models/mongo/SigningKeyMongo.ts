///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import {
    BaseMongoEntity,
    DocDecorators,
    ModelDecorators,
    PersistenceDecorators,
} from "@rapidrest/service-core";
import { ObjectDecorators } from "@rapidrest/core";
import { SigningKey, SigningKeyStatus } from "../types.js";

const { Description } = DocDecorators;
const { DataStore, Identifier, Protect } = ModelDecorators;
const { Nullable } = ObjectDecorators;
const { Column, Entity, Index } = PersistenceDecorators;

/**
 * Implementation of the `SigningKey` interface for storage in a MongoDB database. If SQL is desired, please use
 * `models.sql.SigningKeySQL` instead.
 *
 * @author Jean-Philippe Steinmetz
 */
@DataStore("mongo")
@Entity()
@Description("Defines a single asymmetric key pair used to sign tokens issued by this authorization server.")
@Protect(
    {
        uid: "SigningKey",
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
export class SigningKeyMongo extends BaseMongoEntity implements SigningKey {
    @Column()
    @Identifier
    @Index("kid", { unique: true })
    public kid: string = "";

    @Column()
    public alg: "RS256" = "RS256";

    @Column()
    public publicKeyJwk: any = {};

    @Column()
    public privateKeyEncrypted: string = "";

    @Column()
    @Index("signingkey_status")
    public status: SigningKeyStatus = SigningKeyStatus.ACTIVE;

    @Column()
    public activatedAt: Date = new Date();

    @Column()
    @Nullable
    public retiredAt?: Date;

    constructor(other?: Partial<SigningKeyMongo>) {
        super(other);

        if (other) {
            this.kid = other.kid !== undefined ? other.kid : this.kid;
            this.alg = other.alg !== undefined ? other.alg : this.alg;
            this.publicKeyJwk = other.publicKeyJwk !== undefined ? other.publicKeyJwk : this.publicKeyJwk;
            this.privateKeyEncrypted = other.privateKeyEncrypted !== undefined ? other.privateKeyEncrypted : this.privateKeyEncrypted;
            this.status = other.status !== undefined ? other.status : this.status;
            this.activatedAt = other.activatedAt !== undefined ? other.activatedAt : this.activatedAt;
            this.retiredAt = other.retiredAt !== undefined ? other.retiredAt : this.retiredAt;
        }
    }
}
