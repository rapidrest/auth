////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseAuthFIDO2RouteSQL } from "../../../src/sql";
const { Route } = RouteDecorators;

@Route("/sql/auth/fido2")
export class AuthFIDO2Route extends BaseAuthFIDO2RouteSQL {}
