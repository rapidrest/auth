///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AliasSQL, SecretSQL, UserSQL } from "../../sql.js";
import { BaseAuthFIDO2Route } from "../BaseAuthFIDO2Route.js";

export abstract class BaseAuthFIDO2RouteSQL extends BaseAuthFIDO2Route<UserSQL, AliasSQL, SecretSQL> {
    protected aliasClass: any = AliasSQL;
    protected secretClass: any = SecretSQL;
    protected userClass: any = UserSQL;
}
