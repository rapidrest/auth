///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DefaultAccounts } from "../DefaultAccounts.js";
import { AliasSQL, ProfileSQL, SecretSQL, UserSQL } from "../../models/sql/index.js";

export class DefaultAccountsSQL extends DefaultAccounts<UserSQL, AliasSQL, ProfileSQL, SecretSQL> {
    protected aliasClass: any = AliasSQL;
    protected profileClass: any = ProfileSQL;
    protected secretClass: any = SecretSQL;
    protected userClass: any = UserSQL;
}
