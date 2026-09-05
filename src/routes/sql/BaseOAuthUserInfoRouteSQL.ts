///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ProfileSQL, SigningKeySQL } from "../../models/sql/index.js";
import { BaseOAuthUserInfoRoute } from "../BaseOAuthUserInfoRoute.js";

export abstract class BaseOAuthUserInfoRouteSQL extends BaseOAuthUserInfoRoute<ProfileSQL> {
    protected profileClass: any = ProfileSQL;
    protected signingKeyClass: any = SigningKeySQL;
}
