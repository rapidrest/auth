////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { SecretSQL } from "../../../src/models/sql/SecretSQL";
import { BaseSecretRouteSQL } from "../../../src/routes/sql/BaseSecretRouteSQL";
const { Model, Route } = RouteDecorators;

@Model(SecretSQL)
@Route("/sql/secrets")
export class SecretRoute extends BaseSecretRouteSQL {}
