///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ObjectDecorators } from "@rapidrest/core";

const { Logger } = ObjectDecorators;

/**
 * One durable audit-log entry recorded via `AuditLogUtils.record()`. Deliberately its own shape, not a
 * pass-through of whatever payload an individual `EventUtils.record()` call site happens to build - field
 * names are unified across every call site in this library (e.g. `actorUid`, not `deletedBy`/`revokedBy`)
 * since this is a separate, single mechanism with its own contract.
 */
export interface AuditLogEntry {
    /**
     * A stable identifier for what happened, curated to the set of security-relevant actions this
     * mechanism audits (see `AuthEventType` in `./events.js`). Reuses the matching `AuthEventType` string
     * value wherever one already fits the same event, so the two sinks (`EventUtils`/`AuditLogUtils`)
     * agree on vocabulary for anything they both record.
     */
    type: string;
    /** The account this entry is about - the one the action was performed on or affects. */
    userUid?: string;
    /**
     * Who performed the action, only set when different from `userUid` - e.g. a trusted-role holder
     * impersonating, deleting, or revoking sessions for another account. Mirrors `BaseAccountRoute`'s
     * pre-existing `deletedBy`/`revokedBy` fields, unified under one consistent name for this mechanism.
     */
    actorUid?: string;
    /** The source IP address of the request that triggered this entry, if known. */
    ip?: string;
    /** The request path that triggered this entry, if known. */
    path?: string;
    /**
     * E.g. the authentication method for a `SIGNED_IN` entry (`"password"`, `"passkey"`, `"mfa"`, ...), or
     * the secondary method used for an `ELEVATED` entry - whatever "how" is meaningful for `type`.
     */
    method?: string;
    /** Any additional, entry-type-specific detail not already covered by the fields above. */
    data?: Record<string, unknown>;
}

/**
 * Records durable audit-log entries for a curated set of security-relevant actions (see `AuthEventType`
 * in `./events.js`) - a separate mechanism from, and NOT a replacement for, `@rapidrest/core`'s
 * `EventUtils.record()`. `EventUtils` is lossy, best-effort telemetry: with no `telemetry_services:url`
 * configured and no `EventUtils.on()` listener registered, every event it records is silently discarded
 * end to end - fine for telemetry, unacceptable for an audit log. This class exists because an audit log
 * needs the opposite guarantee - durable, queryable, attributable - which a generic library class can't
 * provide on its own without knowing the consuming app's actual persistence layer.
 *
 * This base implementation only logs (via `@Logger`), which is still a real improvement over
 * `EventUtils`'s silent no-op today - visible in server logs with zero extra configuration. A consuming
 * app that wants a real, durable, queryable audit trail (strongly recommended for production) registers a
 * database-backed subclass under this exact class name (`AuditLogUtils`), so `ObjectFactory` resolves
 * every `@Inject(AuditLogUtils)` in this library to that richer implementation instead - precisely how
 * `MessagingUtils` is swapped for a database-backed implementation elsewhere in this library (see e.g.
 * `BaseSecretRoute`'s `@Inject(MessagingUtils)`), with zero code changes needed in this repo beyond
 * declaring this class and calling `record()`.
 *
 * @author Jean-Philippe Steinmetz
 */
export class AuditLogUtils {
    @Logger
    protected logger: any;

    /**
     * Records one audit-log entry. Never throws - a logging failure here must never be allowed to
     * propagate and fail the caller's real operation - so this wraps its own body in try/catch as a
     * belt-and-suspenders measure, even though every call site in this library already independently
     * guards its own call to this method too.
     */
    public async record(entry: AuditLogEntry): Promise<void> {
        try {
            this.logger?.info(`[AuditLog] ${JSON.stringify(entry)}`);
        } catch (err) {
            // Swallowed intentionally - see the doc comment above. There's nothing meaningful to do with a
            // failure to even log, and no lower-level sink to fall back to here.
        }
    }
}
