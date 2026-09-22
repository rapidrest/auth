///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AuditLogUtils } from "../../src/auth/AuditLogUtils.js";

describe("AuditLogUtils Tests", () => {
    describe("record", () => {
        it("Logs the entry as a JSON string at info level.", async () => {
            const auditLogUtils = new AuditLogUtils();
            const info = vi.fn();
            (auditLogUtils as any).logger = { info };

            await auditLogUtils.record({ type: "auth.signed_in", userUid: "user-1", method: "password" });

            expect(info).toHaveBeenCalledTimes(1);
            const [message] = info.mock.calls[0];
            expect(message).toContain("[AuditLog]");
            expect(JSON.parse(message.replace("[AuditLog] ", ""))).toEqual({
                type: "auth.signed_in",
                userUid: "user-1",
                method: "password",
            });
        });

        it("Does not throw when no logger is set.", async () => {
            const auditLogUtils = new AuditLogUtils();

            await expect(auditLogUtils.record({ type: "auth.signed_in" })).resolves.toBeUndefined();
        });

        it("Does not throw even if the logger itself throws.", async () => {
            const auditLogUtils = new AuditLogUtils();
            (auditLogUtils as any).logger = {
                info: () => {
                    throw new Error("logger exploded");
                },
            };

            await expect(auditLogUtils.record({ type: "auth.signed_in" })).resolves.toBeUndefined();
        });
    });
});
