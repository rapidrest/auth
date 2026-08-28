/**
 * Cuts a new release: bumps the version (via `npm version`, using `semver` to compute the
 * target), moves the RELEASE_NOTES.md "Unreleased" section under the new version heading,
 * records the commits since the last tag in CHANGELOG.md, then commits, tags, and pushes.
 *
 * Usage:
 *   yarn release <major|minor|patch|premajor|preminor|prepatch|prerelease|x.y.z> [options]
 *
 * Options:
 *   --preid=<id>   Prerelease identifier (e.g. "rc") for pre* strategies.
 *   --dry-run      Print the computed version and exit without changing anything.
 *   --no-push      Commit and tag locally but skip `git push`.
 */
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import semver, { type ReleaseType } from "semver";

const ROOT = path.resolve(import.meta.dirname, "..");
const PKG_PATH = path.join(ROOT, "package.json");
const RELEASE_NOTES_PATH = path.join(ROOT, "RELEASE_NOTES.md");
const CHANGELOG_PATH = path.join(ROOT, "CHANGELOG.md");
const UNRELEASED_HEADING = "## Unreleased";

const RELEASE_TYPES: ReleaseType[] = ["major", "minor", "patch", "premajor", "preminor", "prepatch", "prerelease"];

interface Args {
    bump?: string;
    preid?: string;
    dryRun: boolean;
    push: boolean;
}

function parseArgs(argv: string[]): Args {
    const args: Args = { dryRun: false, push: true };
    for (const arg of argv) {
        if (arg === "--dry-run") args.dryRun = true;
        else if (arg === "--no-push") args.push = false;
        else if (arg.startsWith("--preid=")) args.preid = arg.slice("--preid=".length);
        else if (!arg.startsWith("--")) args.bump = arg;
        else throw new Error(`Unknown option: ${arg}`);
    }
    return args;
}

function run(command: string, args: string[], options: { silent?: boolean; shell?: boolean } = {}): string {
    const result = spawnSync(command, args, {
        cwd: ROOT,
        encoding: "utf-8",
        shell: options.shell ?? false,
        stdio: options.silent ? "pipe" : "inherit",
    });
    if (result.status !== 0) {
        throw new Error(`Command failed: ${command} ${args.join(" ")}\n${result.stderr ?? ""}`);
    }
    return (result.stdout ?? "").trim();
}

function assertCleanWorkingTree(): void {
    const status = spawnSync("git", ["status", "--porcelain"], { cwd: ROOT, encoding: "utf-8" }).stdout.trim();
    if (status.length > 0) {
        throw new Error("Working tree is not clean. Commit or stash your changes before releasing.");
    }
}

function computeNewVersion(currentVersion: string, bump: string | undefined, preid: string | undefined): string {
    if (!bump) {
        throw new Error(
            `Usage: yarn release <${RELEASE_TYPES.join("|")}|x.y.z> [--preid=<id>] [--dry-run] [--no-push]`,
        );
    }
    if ((RELEASE_TYPES as string[]).includes(bump)) {
        const next = semver.inc(currentVersion, bump as ReleaseType, preid);
        if (!next) {
            throw new Error(`Could not compute the next version from ${currentVersion} using strategy "${bump}".`);
        }
        return next;
    }
    if (semver.valid(bump)) {
        if (!semver.gt(bump, currentVersion)) {
            throw new Error(`New version ${bump} must be greater than the current version ${currentVersion}.`);
        }
        return bump;
    }
    throw new Error(`"${bump}" is not a valid release strategy or semver version.`);
}

function updateReleaseNotes(version: string): void {
    const notes = readFileSync(RELEASE_NOTES_PATH, "utf-8");
    if (!notes.includes(UNRELEASED_HEADING)) {
        throw new Error(`No "${UNRELEASED_HEADING}" section found in ${RELEASE_NOTES_PATH}.`);
    }
    writeFileSync(RELEASE_NOTES_PATH, notes.replace(UNRELEASED_HEADING, `## v${version}`));
}

function previousTag(): string | undefined {
    const result = spawnSync("git", ["describe", "--tags", "--abbrev=0"], { cwd: ROOT, encoding: "utf-8" });
    return result.status === 0 ? result.stdout.trim() : undefined;
}

function updateChangelog(version: string): void {
    const prevTag = previousTag();
    const range = prevTag ? `${prevTag}..HEAD` : "HEAD";
    const log = run("git", ["log", range, "--no-merges", "--pretty=format:* %s (%h)"], { silent: true });
    const date = new Date().toISOString().slice(0, 10);
    const entry = `## v${version} (${date})\n\n${log.length > 0 ? log : "* No changes recorded."}\n\n`;

    const existing = existsSync(CHANGELOG_PATH) ? readFileSync(CHANGELOG_PATH, "utf-8") : "";
    const header = "# Changelog\n\n";
    const body = existing.startsWith(header) ? existing.slice(header.length) : existing;
    writeFileSync(CHANGELOG_PATH, `${header}${entry}${body}`);
}

function main(): void {
    const args = parseArgs(process.argv.slice(2));
    const pkg = JSON.parse(readFileSync(PKG_PATH, "utf-8")) as { version: string };
    const newVersion = computeNewVersion(pkg.version, args.bump, args.preid);

    if (args.dryRun) {
        console.log(`Dry run: ${pkg.version} -> ${newVersion} (no changes made)`);
        return;
    }

    assertCleanWorkingTree();

    // --no-git-tag-version: this script does its own combined commit/tag below.
    // --ignore-scripts: skip the project's own pre/post-version hooks (e.g. an old postversion
    // that pushes) so this script fully owns the release flow, on any npm project it's dropped into.
    if (process.platform === "win32") {
        // Node's shell:true concatenates an args array unescaped (DEP0190), so build one command string instead.
        run(`npm version ${newVersion} --no-git-tag-version --ignore-scripts`, [], { shell: true });
    } else {
        run("npm", ["version", newVersion, "--no-git-tag-version", "--ignore-scripts"]);
    }
    updateReleaseNotes(newVersion);
    updateChangelog(newVersion);

    const lockFiles = ["package-lock.json", "yarn.lock"].filter((file) => existsSync(path.join(ROOT, file)));
    run("git", ["add", "package.json", ...lockFiles, "RELEASE_NOTES.md", "CHANGELOG.md"]);
    run("git", ["commit", "-m", newVersion]);
    run("git", ["tag", `v${newVersion}`]);

    if (args.push) {
        run("git", ["push"]);
        run("git", ["push", "--tags"]);
    } else {
        console.log("Skipping push (--no-push). Run `git push && git push --tags` when ready.");
    }
}

main();
