///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ACLAction, BaseMongoEntity, DocDecorators, ModelDecorators, PersistenceDecorators } from "@rapidrest/service-core";
import { ObjectDecorators } from "@rapidrest/core";
import { Client, ClientType, TokenEndpointAuthMethod } from "../types.js";

const { Description } = DocDecorators;
const { DataStore, Protect } = ModelDecorators;
const { Nullable } = ObjectDecorators;
const { Column, Entity, Index } = PersistenceDecorators;

/**
 * Implementation of the `Client` interface for storage in a MongoDB database. If SQL is desired, please use
 * `models.sql.ClientSQL` instead.
 *
 * @author Jean-Philippe Steinmetz
 */
@DataStore("mongo")
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
export class ClientMongo extends BaseMongoEntity implements Client {
    @Column()
    @Nullable
    public clientSecretHash?: string;

    @Column()
    public clientType: ClientType = ClientType.CONFIDENTIAL;

    @Column()
    public clientName: string = "";

    @Column()
    public redirectUris: string[] = [];

    @Column()
    public grantTypes: string[] = [];

    @Column()
    public responseTypes: string[] = [];

    @Column()
    public scope: string = "";

    @Column()
    public tokenEndpointAuthMethod: TokenEndpointAuthMethod = TokenEndpointAuthMethod.CLIENT_SECRET_BASIC;

    @Column()
    public requirePkce: boolean = false;

    @Column()
    @Nullable
    public jwksUri?: string;

    @Column()
    @Nullable
    public jwks?: any;

    @Column()
    @Nullable
    public contacts?: string[];

    @Column()
    @Nullable
    public logoUri?: string;

    @Column()
    @Nullable
    public clientUri?: string;

    @Column()
    @Nullable
    public tosUri?: string;

    @Column()
    @Nullable
    public policyUri?: string;

    @Column()
    @Nullable
    public softwareId?: string;

    @Column()
    @Nullable
    public softwareVersion?: string;

    @Column()
    @Index("client_ownerUid")
    @Nullable
    public ownerUid?: string;

    @Column()
    public firstParty: boolean = false;

    @Column()
    @Nullable
    public registrationAccessTokenHash?: string;

    @Column()
    @Nullable
    public disabled?: boolean;

    constructor(other?: Partial<ClientMongo>) {
        super(other);

        if (other) {
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
