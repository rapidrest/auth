///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
import { DefaultAccounts } from "../DefaultAccounts.js";
import { AliasMongo, ProfileMongo, SecretMongo, UserMongo } from "../../mongo.js";

export class DefaultAccountsMongo extends DefaultAccounts<UserMongo, AliasMongo, ProfileMongo, SecretMongo> {
    protected aliasClass: any = AliasMongo;
    protected profileClass: any = ProfileMongo;
    protected secretClass: any = SecretMongo;
    protected userClass: any = UserMongo;
}
