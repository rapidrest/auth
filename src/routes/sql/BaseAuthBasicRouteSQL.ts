///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import { AliasSQL, SecretSQL, UserSQL } from "../../sql.js";
import { BaseAuthBasicRoute } from "../BaseAuthBasicRoute.js";

export abstract class BaseAuthBasicRouteSQL extends BaseAuthBasicRoute<UserSQL, SecretSQL, AliasSQL> {
    protected aliasClass: any = AliasSQL;
    protected secretClass: any = SecretSQL;
    protected userClass: any = UserSQL;
}
