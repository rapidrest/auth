///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AuthResult, SystemSettings } from "../../src/models/types.js";

describe("AuthResult", () => {
    it("Copies refresh/token/user from the given object.", () => {
        const user: any = { uid: "user-1" };
        const result = new AuthResult({ refresh: "refresh-token", token: "access-token", user });

        expect(result.refresh).toBe("refresh-token");
        expect(result.token).toBe("access-token");
        expect(result.user).toBe(user);
    });
});

describe("SystemSettings", () => {
    it("Falls back to its class defaults when constructed with no data.", () => {
        const settings = new SystemSettings();

        expect(settings.allowRegistration).toBe(true);
        expect(settings.requireMFA).toBe(false);
    });

    it("Applies provided data when constructed with data.", () => {
        const settings = new SystemSettings({ allowRegistration: false, requireMFA: true });

        expect(settings.allowRegistration).toBe(false);
        expect(settings.requireMFA).toBe(true);
    });

    it("Leaves an omitted field at its class default.", () => {
        expect(new SystemSettings({ allowRegistration: false }).requireMFA).toBe(false);
        expect(new SystemSettings({ requireMFA: true }).allowRegistration).toBe(true);
    });
});
