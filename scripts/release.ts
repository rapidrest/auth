/**
 * Cuts a new release: bumps the version (via `npm version`, using `semver` to compute the
 * target), moves the RELEASE_NOTES.md "Unreleased" section under the new version heading,
 * summarizes the commits since the last tag into a Keep a Changelog-style entry in
 * CHANGELOG.md, then commits, tags, and pushes.
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
const CHANGELOG_UNRELEASED_HEADING = "## [Unreleased]";
const CHANGELOG_DEFAULT_HEADER = `# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

${CHANGELOG_UNRELEASED_HEADING}
`;

/** Commit message lines matching any of these are dropped from the changelog entirely. */
const CHANGELOG_NOISE_PATTERNS: RegExp[] = [
    /^updating (readme\/)?release notes/i,
    /\btests?\b.*\bcoverage\b/i,
    /(claude notes|notes for claude|claude instructions|\.claude\/)/i,
    /^\d+\.\d+\.\d+(-[\w.]+)?$/,
];

type ChangelogCategory = "Added" | "Changed" | "Fixed" | "Removed";
const CHANGELOG_CATEGORY_ORDER: ChangelogCategory[] = ["Added", "Changed", "Fixed", "Removed"];

/**
 * Maps a commit line's leading verb to a changelog category and, where the verb reads
 * awkwardly out of commit-message tense (e.g. "Adding", "Switching"), its changelog-tense
 * replacement. Verbs not listed here default to the "Changed" category with the line left
 * untouched, which also covers noun-led lines like "ObjectFactory now sets...".
 */
const CHANGELOG_VERB_REWRITES: Record<string, { category: ChangelogCategory; word?: string }> = {
    add: { category: "Added", word: "Added" },
    added: { category: "Added" },
    adding: { category: "Added", word: "Added" },
    allow: { category: "Added", word: "Added" },
    allowing: { category: "Added", word: "Added" },
    fix: { category: "Fixed", word: "Fixed" },
    fixed: { category: "Fixed" },
    fixing: { category: "Fixed", word: "Fixed" },
    remove: { category: "Removed", word: "Removed" },
    removed: { category: "Removed" },
    removing: { category: "Removed", word: "Removed" },
    configuring: { category: "Changed", word: "Configured" },
    converting: { category: "Changed", word: "Converted" },
    consolidating: { category: "Changed", word: "Consolidated" },
    exposing: { category: "Changed", word: "Exposed" },
    improving: { category: "Changed", word: "Improved" },
    optimizing: { category: "Changed", word: "Optimized" },
    refactoring: { category: "Changed", word: "Refactored" },
    setting: { category: "Changed", word: "Set" },
    swapping: { category: "Changed", word: "Swapped" },
    switching: { category: "Changed", word: "Switched" },
    updating: { category: "Changed", word: "Updated" },
    upgrading: { category: "Changed", word: "Upgraded" },
};

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

function getRepoUrl(): string {
    const pkg = JSON.parse(readFileSync(PKG_PATH, "utf-8")) as { repository?: string | { url?: string } };
    const raw = typeof pkg.repository === "string" ? pkg.repository : pkg.repository?.url;
    if (!raw) {
        throw new Error(`No "repository" field found in ${PKG_PATH}.`);
    }
    return raw.replace(/^git\+/, "").replace(/\.git$/, "");
}

/** Classifies one line of a commit message into a changelog bullet, or drops it as noise. */
function classifyChangelogLine(line: string): { category: ChangelogCategory; text: string } | null {
    const trimmed = line.trim();
    if (trimmed.length === 0 || CHANGELOG_NOISE_PATTERNS.some((pattern) => pattern.test(trimmed))) {
        return null;
    }

    const match = trimmed.match(/^(\S+)(\s+.*)?$/s);
    if (!match) {
        return { category: "Changed", text: trimmed };
    }
    const [, firstWord, rest = ""] = match;
    const rewrite = CHANGELOG_VERB_REWRITES[firstWord.toLowerCase()];
    if (!rewrite) {
        return { category: "Changed", text: trimmed };
    }
    return { category: rewrite.category, text: rewrite.word ? `${rewrite.word}${rest}` : trimmed };
}

/** Collects and classifies every commit-message line (not just subjects) in `range`, oldest first. */
function collectChangelogBullets(range: string): { category: ChangelogCategory; text: string }[] {
    const raw = run("git", ["log", range, "--no-merges", "--reverse", "--pretty=format:%B%x1e"], { silent: true });
    const bullets: { category: ChangelogCategory; text: string }[] = [];
    for (const body of raw.split("\x1e")) {
        for (const line of body.split("\n")) {
            const bullet = classifyChangelogLine(line);
            if (bullet) bullets.push(bullet);
        }
    }
    return bullets;
}

function buildChangelogEntry(
    version: string,
    date: string,
    bullets: { category: ChangelogCategory; text: string }[],
): string {
    const sections = CHANGELOG_CATEGORY_ORDER.map((category) => {
        const items = bullets.filter((bullet) => bullet.category === category).map((bullet) => `- ${bullet.text}`);
        return items.length > 0 ? `### ${category}\n${items.join("\n")}` : null;
    }).filter((section): section is string => section !== null);

    const body = sections.length > 0 ? sections.join("\n\n") : "_No notable changes._";
    return `## [${version}] - ${date}\n\n${body}\n`;
}

/** Splits the file into the changelog body and its trailing block of `[x.y.z]: url` link definitions. */
function splitChangelogLinks(content: string): { body: string; linkLines: string[] } {
    const lines = content.split("\n");
    let i = lines.length - 1;
    while (i >= 0 && lines[i].trim() === "") i--;
    const linkLines: string[] = [];
    while (i >= 0 && /^\[[^\]]+\]:\s/.test(lines[i])) {
        linkLines.unshift(lines[i]);
        i--;
    }
    return { body: lines.slice(0, i + 1).join("\n"), linkLines };
}

function insertChangelogEntry(body: string, entry: string): string {
    const idx = body.indexOf(CHANGELOG_UNRELEASED_HEADING);
    if (idx === -1) {
        return `${body.trimEnd()}\n\n${CHANGELOG_UNRELEASED_HEADING}\n\n${entry}`;
    }
    const insertAt = idx + CHANGELOG_UNRELEASED_HEADING.length;
    return `${body.slice(0, insertAt)}\n\n${entry}${body.slice(insertAt)}`;
}

function updateChangelogLinks(
    linkLines: string[],
    version: string,
    prevTag: string | undefined,
    repoUrl: string,
): string[] {
    const filtered = linkLines.filter((line) => !line.startsWith("[Unreleased]:") && !line.startsWith(`[${version}]:`));
    const unreleasedLink = `[Unreleased]: ${repoUrl}/compare/v${version}...HEAD`;
    const versionLink = prevTag
        ? `[${version}]: ${repoUrl}/compare/${prevTag}...v${version}`
        : `[${version}]: ${repoUrl}/releases/tag/v${version}`;
    return [unreleasedLink, versionLink, ...filtered];
}

function updateChangelog(version: string): void {
    const repoUrl = getRepoUrl();
    const prevTag = previousTag();
    const range = prevTag ? `${prevTag}..HEAD` : "HEAD";
    const date = new Date().toISOString().slice(0, 10);

    const bullets = collectChangelogBullets(range);
    const entry = buildChangelogEntry(version, date, bullets);

    const existing = existsSync(CHANGELOG_PATH) ? readFileSync(CHANGELOG_PATH, "utf-8") : CHANGELOG_DEFAULT_HEADER;
    const { body, linkLines } = splitChangelogLinks(existing);
    const newBody = insertChangelogEntry(body, entry);
    const newLinkLines = updateChangelogLinks(linkLines, version, prevTag, repoUrl);

    const content = `${newBody.trimEnd()}\n\n${newLinkLines.join("\n")}\n`.replace(/\n{3,}/g, "\n\n");
    writeFileSync(CHANGELOG_PATH, content);
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
