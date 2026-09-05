///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ApiError } from "@rapidrest/core";

/**
 * An OAuth 2.0 error, per RFC 6749 §5.2 — a distinct wire shape (`{error, error_description}`) from this
 * library's usual `ApiError` envelope, since the format here is spec-mandated rather than this library's own
 * convention. Shared by every OAuth endpoint that reports errors this way: `/token` (RFC 6749 §5.2), and
 * `/revoke`/`/introspect` (RFC 7009 §2.2.1 / RFC 7662 §2.3, both of which reuse the same shape for a
 * client-authentication failure).
 */
export class OAuthError extends Error {
    public readonly error: string;
    public readonly errorDescription?: string;
    public readonly status: number;

    constructor(error: string, errorDescription?: string, status: number = 400) {
        super(errorDescription ?? error);
        this.error = error;
        this.errorDescription = errorDescription;
        this.status = status;
    }
}

/** Maps any error thrown while handling an OAuth request into the RFC 6749 §5.2 error shape. */
export function toOAuthError(err: unknown): OAuthError {
    if (err instanceof OAuthError) {
        return err;
    }
    if (err instanceof ApiError) {
        const error = err.status === 401 ? "invalid_client" : err.status >= 500 ? "server_error" : "invalid_request";
        return new OAuthError(error, err.message, err.status);
    }
    return new OAuthError("server_error", undefined, 500);
}
