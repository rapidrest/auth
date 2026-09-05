///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AliasSQL, SecretSQL, UserSQL } from "../../models/sql/index.js";
import { BaseAuthOTPRoute } from "../BaseAuthOTPRoute.js";

export abstract class BaseAuthOTPRouteSQL extends BaseAuthOTPRoute<UserSQL, AliasSQL, SecretSQL> {
    protected aliasClass: any = AliasSQL;
    protected secretClass: any = SecretSQL;
    protected userClass: any = UserSQL;
}
