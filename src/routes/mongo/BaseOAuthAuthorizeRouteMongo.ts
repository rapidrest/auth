///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AuthorizationCodeMongo, ClientMongo, ConsentGrantMongo } from "../../models/mongo/index.js";
import { BaseOAuthAuthorizeRoute } from "../BaseOAuthAuthorizeRoute.js";

export abstract class BaseOAuthAuthorizeRouteMongo extends BaseOAuthAuthorizeRoute<
    ClientMongo,
    AuthorizationCodeMongo,
    ConsentGrantMongo
> {
    protected authorizationCodeClass: any = AuthorizationCodeMongo;
    protected clientClass: any = ClientMongo;
    protected consentGrantClass: any = ConsentGrantMongo;
}
