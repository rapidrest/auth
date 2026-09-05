////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseOAuthDiscoveryRoute, OAuthDiscoveryEndpoints } from "../../../src/routes/BaseOAuthDiscoveryRoute.js";
const { Route } = RouteDecorators;

@Route(["/mongo/.well-known/oauth-authorization-server", "/mongo/.well-known/openid-configuration"])
export class OAuthDiscoveryRoute extends BaseOAuthDiscoveryRoute {
    protected endpoints: OAuthDiscoveryEndpoints = {
        authorization: "http://localhost:3000/mongo/oauth/authorize",
        token: "http://localhost:3000/mongo/oauth/token",
        jwks: "http://localhost:3000/mongo/oauth/jwks",
        userinfo: "http://localhost:3000/mongo/oauth/userinfo",
        revocation: "http://localhost:3000/mongo/oauth/revoke",
        introspection: "http://localhost:3000/mongo/oauth/introspect",
    };
}
