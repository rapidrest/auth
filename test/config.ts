///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2020-2026 Jean-Philippe Steinmetz
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
        // Controls the `Set-Cookie` header written alongside the JWT returned by the various
        // authentication routes. Enabled here so integration tests can verify the cookie is set.
        cookie: {
            enabled: true,
            name: "jwt",
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
