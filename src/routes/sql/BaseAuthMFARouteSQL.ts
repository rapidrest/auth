///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import { AliasSQL, SecretSQL, UserSQL } from "../../sql.js";
import { BaseAuthMFARoute } from "../BaseAuthMFARoute.js";

export abstract class BaseAuthMFARouteSQL extends BaseAuthMFARoute<UserSQL, SecretSQL, AliasSQL> {
    protected aliasClass: any = AliasSQL;
    protected secretClass: any = SecretSQL;
    protected userClass: any = UserSQL;
}
