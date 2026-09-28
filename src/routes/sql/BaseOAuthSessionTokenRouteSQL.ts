///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { SigningKeySQL, UserSQL } from "../../models/sql/index.js";
import { BaseOAuthSessionTokenRoute } from "../BaseOAuthSessionTokenRoute.js";

export abstract class BaseOAuthSessionTokenRouteSQL extends BaseOAuthSessionTokenRoute<UserSQL> {
    protected signingKeyClass: any = SigningKeySQL;
    protected userClass: any = UserSQL;
}
