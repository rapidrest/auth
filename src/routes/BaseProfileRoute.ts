///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import { CRUDRoute } from "@rapidrest/service-core";
import { Profile } from "../models/types.js";

/**
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseProfileRoute<T extends Profile> extends CRUDRoute<T> {}
