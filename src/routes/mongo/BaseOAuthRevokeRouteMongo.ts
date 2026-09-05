///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ClientMongo, OAuthRefreshTokenMongo, SigningKeyMongo } from "../../models/mongo/index.js";
import { BaseOAuthRevokeRoute } from "../BaseOAuthRevokeRoute.js";

export abstract class BaseOAuthRevokeRouteMongo extends BaseOAuthRevokeRoute<ClientMongo, OAuthRefreshTokenMongo> {
    protected clientClass: any = ClientMongo;
    protected refreshTokenClass: any = OAuthRefreshTokenMongo;
    protected signingKeyClass: any = SigningKeyMongo;
}
