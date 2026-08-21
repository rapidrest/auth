////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
// Re-exports the library's SQL model classes so the test Server's ClassLoader (rooted at
// `test/server`) can discover their `@DataStore` metadata alongside the test routes that use them.
export * from "../../../src/models/sql/index.js";
