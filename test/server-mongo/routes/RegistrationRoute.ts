////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseRegistrationRouteMongo } from "../../../src/mongo";
const { Route } = RouteDecorators;

@Route("/mongo/registration")
export class RegistrationRoute extends BaseRegistrationRouteMongo {}
