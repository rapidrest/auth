///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import "reflect-metadata";
import { ObjectDecorators } from "@rapidrest/core";
import { RouteDecorators, DocDecorators, HttpResponse, RepoUtils, ObjectFactory } from "@rapidrest/service-core";
import { SigningKey } from "../models/types.js";
import { SigningKeyUtils } from "../auth/SigningKeyUtils.js";

const { Init } = ObjectDecorators;
const { Summary, Description, Returns } = DocDecorators;
const { Get, Response } = RouteDecorators;

/**
 * Serves this authorization server's public JSON Web Key Set (RFC 7517) at whatever path a subclass
 * mounts it to (conventionally `/.well-known/jwks.json` or `/jwks.json`), so relying parties and resource
 * servers can verify the tokens this server issues without any prior key exchange. Kept as its own route
 * class separate from `BaseOAuthDiscoveryRoute` since a JWKS endpoint is typically polled far more often
 * than discovery metadata and may warrant independent caching/CDN treatment.
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseOAuthJwksRoute<K extends SigningKey> {
    protected abstract signingKeyClass: any;

    // Automatically injected by ObjectFactory on instantiation
    private _objectFactory?: ObjectFactory;

    protected signingKeyRepo?: RepoUtils<K>;

    protected signingKeyUtils?: SigningKeyUtils;

    /**
     * Called on server startup to initialize the route with any defaults.
     */
    @Init
    private async initialize(): Promise<void> {
        if (!this._objectFactory) {
            throw new Error("objectFactory is not set.");
        }

        if (!this.signingKeyRepo && this.signingKeyClass) {
            this.signingKeyRepo = await this._objectFactory.newInstance(RepoUtils, {
                name: this.signingKeyClass.name,
                args: [this.signingKeyClass],
            });
        }

        if (!this.signingKeyUtils && this.signingKeyRepo) {
            this.signingKeyUtils = await this._objectFactory.newInstance(SigningKeyUtils, {
                name: "default",
                args: [this.signingKeyRepo],
            });
        }
    }

    /**
     * Returns this authorization server's public JSON Web Key Set. Never includes private key material —
     * see `SigningKeyUtils.getPublicJwks()`.
     */
    @Summary("JSON Web Key Set")
    @Description(
        "Returns this authorization server's public JSON Web Key Set (RFC 7517), used to verify the " +
            "signature of tokens it has issued.",
    )
    @Returns([Object])
    @Get()
    public async jwks(@Response res: HttpResponse): Promise<{ keys: any[] }> {
        if (!this.signingKeyUtils) {
            throw new Error("signingKeyUtils is not set.");
        }

        const result = await this.signingKeyUtils.getPublicJwks();
        res.setHeader("Cache-Control", `public, max-age=${this.signingKeyUtils.getJwksCacheMaxAgeSeconds()}`);
        return result;
    }
}
