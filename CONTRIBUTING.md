# Contributing

Thank you for your interest in contributing! This repository is part of the
[RapidREST](https://rapidrest.dev) project which is composed of multiple repositories stored
on [GitHub](https://github.com/rapidrest). The same contribution process applies across
all repositories.

## Reporting bugs and requesting features

Please use this repository's Issues tab — file bugs and feature requests against whichever
RapidREST repository they actually concern.

### Bug Reports

A good bug report includes:

- **Steps to Reproduce** the bug (a minimal code sample is ideal).
- What you **Expected** to happen, and what happened instead (**Actual**)
- The **Reproduction Rate** (e.g. 3/3 with a minimum 3 tries) (**Repo Rate**)
- The **Severity** of the bug (e.g. _BLOCKER_, _HIGH_, _MEDIUM_, _LOW_)
- The **Project Info** containing the version of this package, dependent @rapidrest packages (e.g. core, service-core, cli), and your Node.js version
- Include screenshots, crashdumps, logs, etc. when possible

Make sure to be as detailed as possible.

#### Example

```
Steps to Reproduce:
1. Configure `OIDCStrategy` with a valid issuer and client credentials
2. Complete the OIDC login flow in a browser
3. Inspect the resulting session (`req.user`)

Repro Rate: 3/3

Expected:
The authenticated user's `roles` claim from the ID token is applied to the session

Actual:
`req.user.roles` is empty
// Insert token payload (redacted), server logs

Severity: HIGH

Project Info:
@rapidrest/auth: v1.0.0
@rapidrest/service-core: v1.2.1
NodeJS: 24.0
```

### Feature Requests

For feature requests, please provide a description of the use case and how it relates to you as a developer or as an end-user.

Good feature requests start with the phrase "As a [developer|end-user] I would like the ability to..."

#### Example

```
As a developer I would like a `SAMLStrategy` alongside the existing OIDC/OTP/Passkey strategies,
so I can integrate with enterprise identity providers that only support SAML 2.0.
```

## Development setup

This project uses [Yarn](https://yarnpkg.com) (via Corepack) and requires Node.js `>=24.0.0`.

```sh
git clone <this-repo>
cd <this-repo>
corepack enable
yarn install
```

## Making changes

1. Create a branch off `main` for your change.
2. Keep changes focused to a single bug or feature.
3. Add or update tests for any behavior you change. Check `vitest.config.ts` for this project's
   coverage requirements.
4. Before opening a pull request, make sure everything passes:

    ```sh
    yarn install
    yarn build
    yarn test
    ```

5. Write commit messages that explain _why_, not just _what_ — the diff already shows what
   changed. Keep the first line short and imperative (e.g. "Fix path traversal in export output"),
   with further detail in the body if needed.

## Pull requests

- Describe what the change does and why, and link any related issue.
- Keep the PR scoped to one concern — it's fine to open several small PRs rather than one large one.
- CI must pass (lint, tests, build) before a PR can be merged.
- Be responsive to review feedback; if a change needs discussion, that's normal and expected.

## Attribution

Contributions are recognized in this repository's `CONTRIBUTORS.md`. Feel free to add yourself
in the same commit as your first contribution.

By submitting a contribution, you agree it will be licensed under this repository's `LICENSE`.

## Questions

If anything here is unclear, open an issue — that's useful feedback on this guide too.
