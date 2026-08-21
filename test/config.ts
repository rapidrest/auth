///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2020-2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import nconf from "nconf";
const conf = nconf.argv().env({
    separator: "__",
    lowerCase: true,
    parseValues: true,
});

conf.use("memory");

conf.defaults({
    service_name: "api_service",
    version: "1.0",
    cookie_secret: "f0fLSKFJLKWJFe09f32joff098u2fOFIWJ32890fnfnlak",
    cors: {
        origins: ["http://localhost:3000"],
    },
    datastores: {
        acl: {
            type: "mongodb",
            url: "mongodb://localhost:9999/acls",
            synchronize: true,
        },
        mongo: {
            type: "mongodb",
            host: "localhost",
            port: 9999,
            database: "rrst-test",
            synchronize: true,
        },
        sql: {
            type: "sqlite",
            host: "localhost",
            database: "rrst-test",
            synchronize: true,
        },
    },
    // Specifies the group names that are considered to be trusted with administrative privileges.
    trusted_roles: ["admin"],
    // Settings pertaining to the signing and verification of authentication tokens
    auth: {
        // The default authentication strategy to use
        strategy: "auth.JWTStrategy",
        allowQueryParam: true,
        // The password to be used when signing or verifying authentication tokens
        secret: "MyPasswordIsSecure",
        options: {
            // "algorithm": "HS256",
            expiresIn: "7 days",
            audience: "mydomain.com",
            issuer: "api.mydomain.com",
        },
        // Settings for the long-lived refresh token issued alongside every access token.
        refresh: {
            expiresIn: "14 days",
        },
        // Settings for elevated access tokens issued after a fresh re-authentication (see
        // BaseAuthElevationRoute). Deliberately short-lived relative to `options.expiresIn` above, since an
        // elevated token also carries trusted roles that a normal token does not.
        elevated: {
            expiresIn: "15m",
        },
        // Controls the `Set-Cookie` header(s) written alongside the JWT/refresh token returned by the
        // various authentication routes. Enabled here so integration tests can verify the cookies are set.
        cookie: {
            enabled: true,
            access: {
                name: "jwt",
            },
            refresh: {
                name: "refresh",
            },
        },
        oidc: {
            name: "test",
            authorizationURL: "https://oidc-test.com/authorize",
            clientID: "123457890",
            clientSecret: "f32fa983732aq9rf7ab39f",
            profileURL: "https://oidc-test.com/userinfo",
            protocol: "openid",
            redirectURI: "http://localhost:3000",
            tokenURL: "https://oidc-test.com/profile",
        },
        passkey: {
            rpName: "rapidrest",
            rpID: "rapidrest",
            origin: "http://localhost:3000",
        },
        fido2: {
            rpName: "rapidrest",
            rpID: "rapidrest",
            origin: "http://localhost:3000",
            authenticatorAttachment: "cross-platform",
            residentKey: "discouraged",
        },
        totp: {
            issuer: "rapidrest",
            digits: 6,
            period: 30,
            algorithm: "sha1",
            epochTolerance: [5, 0],
        },
    },
    oauth_provider: {
        name: "oauth_test",
        /** STUB: Will be filled out by test. */
    },
    rbac: {
        enabled: true,
    },
    session: {
        secret: "SessionsHaveSecrets",
        cookieName: "rrst.sid",
        ttl: 300,
    },
    cluster_url: "http://localhost",
    metrics: {
        authRequired: false,
    },
});

export default conf;
