///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AuthorizationCodeSQL, ClientSQL, SigningKeySQL } from "../../models/sql/index.js";
import { BaseOAuthTokenRoute } from "../BaseOAuthTokenRoute.js";

export abstract class BaseOAuthTokenRouteSQL extends BaseOAuthTokenRoute<ClientSQL, AuthorizationCodeSQL> {
    protected authorizationCodeClass: any = AuthorizationCodeSQL;
    protected clientClass: any = ClientSQL;
    protected signingKeyClass: any = SigningKeySQL;
}
