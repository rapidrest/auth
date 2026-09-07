///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { UserSQL } from "../../models/sql/index.js";
import { BaseImpersonationRoute } from "../BaseImpersonationRoute.js";

export class BaseImpersonationRouteSQL extends BaseImpersonationRoute<UserSQL> {
    protected userClass: any = UserSQL;
}
