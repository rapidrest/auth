///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ACLAction, BaseEntity, DocDecorators, ModelDecorators, PersistenceDecorators } from "@rapidrest/service-core";
import { ObjectDecorators } from "@rapidrest/core";
import { Client, ClientType, TokenEndpointAuthMethod } from "../types.js";

const { Description } = DocDecorators;
const { DataStore, Identifier, Protect } = ModelDecorators;
const { Nullable } = ObjectDecorators;
const { Column, Entity, Index } = PersistenceDecorators;

/**
 * Implementation of the `Client` interface for storage in a SQL database. If MongoDB is desired, please use
 * `models.mongo.ClientMongo` instead.
 *
 * @author Jean-Philippe Steinmetz
 */
@DataStore("sql")
@Entity()
@Description("Defines a single OAuth 2.0 / OpenID Connect client application registered with this authorization server.")
@Protect(
    {
        uid: "Client",
        records: [
            {
                userOrRoleId: "anonymous",
                actions: [],
            },
            {
                userOrRoleId: ".*",
                actions: [ACLAction.CREATE],
            },
        ],
    },
    true,
)
export class ClientSQL extends BaseEntity implements Client {
    @Column()
    @Identifier
    @Index("clientId", { unique: true })
    public clientId: string = "";

    @Column({ nullable: true })
    @Nullable
    public clientSecretHash?: string;

    @Column({ type: "varchar" })
    public clientType: ClientType = ClientType.CONFIDENTIAL;

    @Column()
    public clientName: string = "";

    @Column({ type: "simple-json" })
    public redirectUris: string[] = [];

    @Column({ type: "simple-json" })
    public grantTypes: string[] = [];

    @Column({ type: "simple-json" })
    public responseTypes: string[] = [];

    @Column()
    public scope: string = "";

    @Column({ type: "varchar" })
    public tokenEndpointAuthMethod: TokenEndpointAuthMethod = TokenEndpointAuthMethod.CLIENT_SECRET_BASIC;

    @Column()
    public requirePkce: boolean = false;

    @Column({ nullable: true })
    @Nullable
    public jwksUri?: string;

    @Column({ type: "simple-json", nullable: true })
    @Nullable
    public jwks?: any;

    @Column({ type: "simple-json", nullable: true })
    @Nullable
    public contacts?: string[];

    @Column({ nullable: true })
    @Nullable
    public logoUri?: string;

    @Column({ nullable: true })
    @Nullable
    public clientUri?: string;

    @Column({ nullable: true })
    @Nullable
    public tosUri?: string;

    @Column({ nullable: true })
    @Nullable
    public policyUri?: string;

    @Column({ nullable: true })
    @Nullable
    public softwareId?: string;

    @Column({ nullable: true })
    @Nullable
    public softwareVersion?: string;

    @Column({ nullable: true })
    @Index("client_ownerUid")
    @Nullable
    public ownerUid?: string;

    @Column()
    public firstParty: boolean = false;

    @Column({ nullable: true })
    @Nullable
    public registrationAccessTokenHash?: string;

    @Column({ nullable: true })
    @Nullable
    public disabled?: boolean;

    constructor(other?: Partial<ClientSQL>) {
        super(other);

        if (other) {
            this.clientId = other.clientId !== undefined ? other.clientId : this.clientId;
            this.clientSecretHash = other.clientSecretHash !== undefined ? other.clientSecretHash : this.clientSecretHash;
            this.clientType = other.clientType !== undefined ? other.clientType : this.clientType;
            this.clientName = other.clientName !== undefined ? other.clientName : this.clientName;
            this.redirectUris = other.redirectUris !== undefined ? other.redirectUris : this.redirectUris;
            this.grantTypes = other.grantTypes !== undefined ? other.grantTypes : this.grantTypes;
            this.responseTypes = other.responseTypes !== undefined ? other.responseTypes : this.responseTypes;
            this.scope = other.scope !== undefined ? other.scope : this.scope;
            this.tokenEndpointAuthMethod =
                other.tokenEndpointAuthMethod !== undefined ? other.tokenEndpointAuthMethod : this.tokenEndpointAuthMethod;
            this.requirePkce = other.requirePkce !== undefined ? other.requirePkce : this.requirePkce;
            this.jwksUri = other.jwksUri !== undefined ? other.jwksUri : this.jwksUri;
            this.jwks = other.jwks !== undefined ? other.jwks : this.jwks;
            this.contacts = other.contacts !== undefined ? other.contacts : this.contacts;
            this.logoUri = other.logoUri !== undefined ? other.logoUri : this.logoUri;
            this.clientUri = other.clientUri !== undefined ? other.clientUri : this.clientUri;
            this.tosUri = other.tosUri !== undefined ? other.tosUri : this.tosUri;
            this.policyUri = other.policyUri !== undefined ? other.policyUri : this.policyUri;
            this.softwareId = other.softwareId !== undefined ? other.softwareId : this.softwareId;
            this.softwareVersion = other.softwareVersion !== undefined ? other.softwareVersion : this.softwareVersion;
            this.ownerUid = other.ownerUid !== undefined ? other.ownerUid : this.ownerUid;
            this.firstParty = other.firstParty !== undefined ? other.firstParty : this.firstParty;
            this.registrationAccessTokenHash =
                other.registrationAccessTokenHash !== undefined
                    ? other.registrationAccessTokenHash
                    : this.registrationAccessTokenHash;
            this.disabled = other.disabled !== undefined ? other.disabled : this.disabled;
        }
    }
}
