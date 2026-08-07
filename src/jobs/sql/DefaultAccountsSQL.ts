///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
import { DefaultAccounts } from "../DefaultAccounts.js";
import { AliasSQL, ProfileSQL, SecretSQL, UserSQL } from "../../sql.js";

export class DefaultAccountsSQL extends DefaultAccounts<UserSQL, AliasSQL, ProfileSQL, SecretSQL> {
    protected aliasClass: any = AliasSQL;
    protected profileClass: any = ProfileSQL;
    protected secretClass: any = SecretSQL;
    protected userClass: any = UserSQL;
}
