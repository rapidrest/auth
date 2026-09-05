///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ClientMongo, OAuthRefreshTokenMongo, SigningKeyMongo } from "../../models/mongo/index.js";
import { BaseOAuthIntrospectRoute } from "../BaseOAuthIntrospectRoute.js";

export abstract class BaseOAuthIntrospectRouteMongo extends BaseOAuthIntrospectRoute<ClientMongo, OAuthRefreshTokenMongo> {
    protected clientClass: any = ClientMongo;
    protected refreshTokenClass: any = OAuthRefreshTokenMongo;
    protected signingKeyClass: any = SigningKeyMongo;
}
