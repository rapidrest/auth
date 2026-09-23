///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { CsrfUtils } from "../../src/auth/CsrfUtils.js";

function makeRes(): any {
    return { appendHeader: vi.fn(), setHeader: vi.fn() };
}

function makeCsrfUtils(config: any = { enabled: true, name: "csrf" }): CsrfUtils {
    const csrfUtils = new CsrfUtils();
    (csrfUtils as any).csrfConfig = config;
    return csrfUtils;
}

describe("CsrfUtils Tests", () => {
    describe("issueToken", () => {
        it("Does nothing when no response is provided.", () => {
            const csrfUtils = makeCsrfUtils();
            expect(() => csrfUtils.issueToken()).not.toThrow();
        });

        it("Does nothing when cookie issuance is disabled (the default).", () => {
            const csrfUtils = new CsrfUtils(); // default config: { enabled: false, name: "csrf" }
            const res = makeRes();

            csrfUtils.issueToken(res);

            expect(res.appendHeader).not.toHaveBeenCalled();
        });

        it("Writes a single, host-only, Secure, SameSite=Lax, non-HttpOnly Set-Cookie header when enabled.", () => {
            const csrfUtils = makeCsrfUtils();
            const res = makeRes();

            csrfUtils.issueToken(res);

            expect(res.setHeader).not.toHaveBeenCalled();
            expect(res.appendHeader).toHaveBeenCalledTimes(1);
            const [, value] = res.appendHeader.mock.calls[0];
            expect(value).toMatch(/^csrf=[A-Za-z0-9_-]+; Path=\/; SameSite=Lax; Secure$/);
            expect(value).not.toContain("Domain=");
            expect(value).not.toContain("HttpOnly");
        });

        it("Generates a different token on every call (no reuse across issuances).", () => {
            const csrfUtils = makeCsrfUtils();
            const res1 = makeRes();
            const res2 = makeRes();

            csrfUtils.issueToken(res1);
            csrfUtils.issueToken(res2);

            const [, value1] = res1.appendHeader.mock.calls[0];
            const [, value2] = res2.appendHeader.mock.calls[0];
            expect(value1).not.toBe(value2);
        });

        it("Honors a custom cookie name, path, maxAge, sameSite and secure:false.", () => {
            const csrfUtils = makeCsrfUtils({
                enabled: true,
                name: "xcsrf",
                path: "/app",
                maxAge: 3600,
                sameSite: "Strict",
                secure: false,
            });
            const res = makeRes();

            csrfUtils.issueToken(res);

            const [, value] = res.appendHeader.mock.calls[0];
            expect(value).toMatch(/^xcsrf=[A-Za-z0-9_-]+; Path=\/app; SameSite=Strict; Max-Age=3600$/);
            expect(value).not.toContain("Secure");
        });
    });

    describe("clearToken", () => {
        it("Does nothing when no response is provided.", () => {
            const csrfUtils = makeCsrfUtils();
            expect(() => csrfUtils.clearToken()).not.toThrow();
        });

        it("Does nothing when cookie issuance is disabled (the default).", () => {
            const csrfUtils = new CsrfUtils();
            const res = makeRes();

            csrfUtils.clearToken(res);

            expect(res.appendHeader).not.toHaveBeenCalled();
        });

        it("Writes a clearing (Max-Age=0) Set-Cookie header when enabled.", () => {
            const csrfUtils = makeCsrfUtils();
            const res = makeRes();

            csrfUtils.clearToken(res);

            expect(res.appendHeader).toHaveBeenCalledTimes(1);
            expect(res.appendHeader).toHaveBeenCalledWith("Set-Cookie", "csrf=; Path=/; SameSite=Lax; Max-Age=0; Secure");
        });

        it("Honors a custom cookie name and path when clearing.", () => {
            const csrfUtils = makeCsrfUtils({ enabled: true, name: "xcsrf", path: "/app" });
            const res = makeRes();

            csrfUtils.clearToken(res);

            expect(res.appendHeader).toHaveBeenCalledWith("Set-Cookie", "xcsrf=; Path=/app; SameSite=Lax; Max-Age=0; Secure");
        });
    });
});
