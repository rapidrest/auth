////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseOAuthDiscoveryRoute, OAuthDiscoveryEndpoints } from "../../../src/routes/BaseOAuthDiscoveryRoute.js";
const { Route } = RouteDecorators;

@Route(["/sql/.well-known/oauth-authorization-server", "/sql/.well-known/openid-configuration"])
export class OAuthDiscoveryRoute extends BaseOAuthDiscoveryRoute {
    protected endpoints: OAuthDiscoveryEndpoints = {
        authorization: "http://localhost:3000/sql/oauth/authorize",
        token: "http://localhost:3000/sql/oauth/token",
        jwks: "http://localhost:3000/sql/oauth/jwks",
        userinfo: "http://localhost:3000/sql/oauth/userinfo",
        revocation: "http://localhost:3000/sql/oauth/revoke",
        introspection: "http://localhost:3000/sql/oauth/introspect",
    };
}
