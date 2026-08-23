///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AliasSQL, ProfileSQL, UserSQL } from "../../sql.js";
import { BaseAuthOIDCRoute } from "../BaseAuthOIDCRoute.js";

export abstract class BaseAuthOIDCRouteSQL extends BaseAuthOIDCRoute<UserSQL, AliasSQL, ProfileSQL> {
    protected aliasClass: any = AliasSQL;
    protected profileClass: any = ProfileSQL;
    protected userClass: any = UserSQL;
}
