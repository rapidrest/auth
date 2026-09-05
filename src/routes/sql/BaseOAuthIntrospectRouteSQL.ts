///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ClientSQL, OAuthRefreshTokenSQL, SigningKeySQL } from "../../models/sql/index.js";
import { BaseOAuthIntrospectRoute } from "../BaseOAuthIntrospectRoute.js";

export abstract class BaseOAuthIntrospectRouteSQL extends BaseOAuthIntrospectRoute<ClientSQL, OAuthRefreshTokenSQL> {
    protected clientClass: any = ClientSQL;
    protected refreshTokenClass: any = OAuthRefreshTokenSQL;
    protected signingKeyClass: any = SigningKeySQL;
}
