///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ClientMongo, SigningKeyMongo, UserMongo } from "../../models/mongo/index.js";
import { BaseOAuthSessionTokenRoute } from "../BaseOAuthSessionTokenRoute.js";

export abstract class BaseOAuthSessionTokenRouteMongo extends BaseOAuthSessionTokenRoute<ClientMongo, UserMongo> {
    protected clientClass: any = ClientMongo;
    protected signingKeyClass: any = SigningKeyMongo;
    protected userClass: any = UserMongo;
}
