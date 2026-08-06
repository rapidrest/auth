////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import { AliasSQL, ProfileSQL, SecretSQL, UserSQL } from "../../sql.js";
import { BaseAccountRoute } from "../BaseAccountRoute.js";

export class BaseAccountRouteSQL extends BaseAccountRoute<UserSQL, AliasSQL, ProfileSQL, SecretSQL> {
    protected aliasClass: any = AliasSQL;
    protected profileClass: any = ProfileSQL;
    protected secretClass: any = SecretSQL;
    protected userClass: any = UserSQL;
}
