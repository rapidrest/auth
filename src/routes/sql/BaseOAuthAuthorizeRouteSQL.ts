///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AuthorizationCodeSQL, ClientSQL, ConsentGrantSQL } from "../../models/sql/index.js";
import { BaseOAuthAuthorizeRoute } from "../BaseOAuthAuthorizeRoute.js";

export abstract class BaseOAuthAuthorizeRouteSQL extends BaseOAuthAuthorizeRoute<ClientSQL, AuthorizationCodeSQL, ConsentGrantSQL> {
    protected authorizationCodeClass: any = AuthorizationCodeSQL;
    protected clientClass: any = ClientSQL;
    protected consentGrantClass: any = ConsentGrantSQL;
}
