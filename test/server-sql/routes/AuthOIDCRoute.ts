////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseAuthOIDCRouteSQL } from "../../../src/sql";
import { OIDCProvider } from "../../../src/auth/OIDCStrategy";
import { ObjectDecorators } from "@rapidrest/core";
const { Config } = ObjectDecorators;
const { Route } = RouteDecorators;

@Route("/sql/auth/oidc")
export class AuthOIDCRoute extends BaseAuthOIDCRouteSQL {
    @Config("auth:oidc")
    protected providerConfig: OIDCProvider = {
        name: "test",
        authorizationURL: "https://oidc-test.com/authorize",
        clientID: "123457890",
        clientSecret: "f32fa983732aq9rf7ab39f",
        profileURL: "https://oidc-test.com/userinfo",
        protocol: "openid",
        redirectURI: "http://localhost:3000",
        tokenURL: "https://oidc-test.com/profile",
    };
}
