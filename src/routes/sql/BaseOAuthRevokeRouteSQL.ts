///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ClientSQL, OAuthRefreshTokenSQL, SigningKeySQL } from "../../models/sql/index.js";
import { BaseOAuthRevokeRoute } from "../BaseOAuthRevokeRoute.js";

export abstract class BaseOAuthRevokeRouteSQL extends BaseOAuthRevokeRoute<ClientSQL, OAuthRefreshTokenSQL> {
    protected clientClass: any = ClientSQL;
    protected refreshTokenClass: any = OAuthRefreshTokenSQL;
    protected signingKeyClass: any = SigningKeySQL;
}
