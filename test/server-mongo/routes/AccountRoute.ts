////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseAccountRouteMongo } from "../../../src/routes/mongo/BaseAccountRouteMongo";
const { Route } = RouteDecorators;

@Route("/mongo/account")
export class AccountRoute extends BaseAccountRouteMongo {}
