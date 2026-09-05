///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { SigningKeySQL } from "../../sql.js";
import { BaseOAuthJwksRoute } from "../BaseOAuthJwksRoute.js";

export abstract class BaseOAuthJwksRouteSQL extends BaseOAuthJwksRoute<SigningKeySQL> {
    protected signingKeyClass: any = SigningKeySQL;
}
