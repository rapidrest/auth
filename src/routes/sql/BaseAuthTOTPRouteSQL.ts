///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import { AliasSQL, SecretSQL, UserSQL } from "../../sql.js";
import { BaseAuthTOTPRoute } from "../BaseAuthTOTPRoute.js";

export abstract class BaseAuthTOTPRouteSQL extends BaseAuthTOTPRoute<UserSQL, AliasSQL, SecretSQL> {
    protected aliasClass: any = AliasSQL;
    protected secretClass: any = SecretSQL;
    protected userClass: any = UserSQL;
}
