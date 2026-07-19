///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import { CRUDRoute } from "@rapidrest/service-core";
import { User } from "../models/types.js";

/**
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseUserRoute<T extends User> extends CRUDRoute<T> {}
