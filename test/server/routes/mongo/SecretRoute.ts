////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseSecretRouteMongo } from "../../../../src/routes/mongo/BaseSecretRouteMongo";
const { Route } = RouteDecorators;

@Route("/mongo/secrets")
export class SecretRoute extends BaseSecretRouteMongo {}
