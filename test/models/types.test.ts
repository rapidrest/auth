///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
import { AuthResult } from "../../src/models/types.js";

describe("AuthResult", () => {
    it("Copies refresh/token/user from the given object.", () => {
        const user: any = { uid: "user-1" };
        const result = new AuthResult({ refresh: "refresh-token", token: "access-token", user });

        expect(result.refresh).toBe("refresh-token");
        expect(result.token).toBe("access-token");
        expect(result.user).toBe(user);
    });
});
