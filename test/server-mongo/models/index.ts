////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
// Re-exports the library's MongoDB model classes so the test Server's ClassLoader (rooted at
// `test/server`) can discover their `@DataStore` metadata alongside the test routes that use them.
export * from "../../../src/models/mongo/index.js";
