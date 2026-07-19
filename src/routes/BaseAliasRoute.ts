///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import { CRUDRoute } from "@rapidrest/service-core";
import { Alias } from "../models/types.js";

/**
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseAliasRoute<T extends Alias> extends CRUDRoute<T> {}
