///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AuthorizationCodeMongo, ClientMongo, OAuthRefreshTokenMongo, SigningKeyMongo } from "../../models/mongo/index.js";
import { BaseOAuthTokenRoute } from "../BaseOAuthTokenRoute.js";

export abstract class BaseOAuthTokenRouteMongo extends BaseOAuthTokenRoute<ClientMongo, AuthorizationCodeMongo, OAuthRefreshTokenMongo> {
    protected authorizationCodeClass: any = AuthorizationCodeMongo;
    protected clientClass: any = ClientMongo;
    protected refreshTokenClass: any = OAuthRefreshTokenMongo;
    protected signingKeyClass: any = SigningKeyMongo;
}
