import * as fs from "node:fs";
import * as path from "node:path";
import { exceeds } from "./engine.js";
import {
  DEFAULT_SCAN_EXTENSIONS,
  formatScanSummaryTerminal,
  globToRegex,
  scanFiles,
} from "./scanner.js";
import type { FileFinding, ScanOptions, ScanSummary } from "./scanner.js";

const IGNORED_DIRS = new Set([
  "node_modules",
  ".git",
  ".svn",
  ".hg",
  "dist",
  "build",
  ".gemini",
  ".turbo",
  ".cache",
]);

export interface WatchOptions extends ScanOptions {
  /** Debounce delay in milliseconds before triggering scan after fs event (default: 150). */
  debounceMs?: number;
  /** Callback fired after every scan completion with the updated summary. */
  onScanComplete?: (summary: ScanSummary) => void;
  /** Whether to clear the terminal before rendering the updated scan summary. */
  clearTerminal?: boolean;
  /** Suppress console output (useful in tests and headless environments). */
  silent?: boolean;
  /** Whether to use ANSI terminal colors in formatted output. */
  colors?: boolean;
}

function toDisplayPath(rootDir: string, absPath: string): string {
  const relPath = path.relative(rootDir, absPath).replace(/\\/g, "/");
  return relPath.startsWith("..") ? absPath.replace(/\\/g, "/") : relPath;
}

function isCandidateFile(
  absPath: string,
  patterns: string[],
  rootDir: string,
  alreadyKnown: boolean,
): boolean {
  if (alreadyKnown) return true;

  const ext = path.extname(absPath).toLowerCase();
  const relFromRoot = path.relative(rootDir, absPath).replace(/\\/g, "/");
  const normalizedAbs = absPath.replace(/\\/g, "/").toLowerCase();

  for (const rawPattern of patterns) {
    const cleanPattern = rawPattern.replace(/^(\.\/|\.\\)+/, "");
    const resolvedPattern = path.resolve(rootDir, cleanPattern);
    const normalizedPattern = resolvedPattern.replace(/\\/g, "/").toLowerCase();

    // Exact file match
    if (normalizedPattern === normalizedAbs) {
      return true;
    }

    // Glob match
    if (/[*?]/.test(cleanPattern)) {
      const regex = globToRegex(cleanPattern);
      const hasSpecificExt = /\.[a-zA-Z0-9_-]+$/.test(cleanPattern);
      if (!hasSpecificExt && !DEFAULT_SCAN_EXTENSIONS.includes(ext as any)) {
        continue;
      }
      if (regex.test(relFromRoot) || regex.test(path.basename(absPath))) {
        return true;
      }
      continue;
    }

    // Directory match
    try {
      if (fs.existsSync(resolvedPattern)) {
        const stat = fs.statSync(resolvedPattern);
        if (stat.isDirectory()) {
          const rel = path.relative(resolvedPattern, absPath);
          if (!rel.startsWith("..") && !path.isAbsolute(rel)) {
            if (DEFAULT_SCAN_EXTENSIONS.includes(ext as any)) {
              return true;
            }
          }
        }
      }
    } catch {
      // Ignore errors when checking pattern path
    }
  }

  return false;
}

/**
 * Interactive file watcher for AgentGuard auditing.
 * Monitors workspace files and directories, triggers debounced incremental scans,
 * and redraws terminal output with rich codeframes.
 */
export class AgentGuardWatcher {
  private patterns: string[];
  private options: WatchOptions;
  private isWatching = false;
  private fsWatchers: fs.FSWatcher[] = [];
  private watchedDirs = new Set<string>();
  private debounceTimer: NodeJS.Timeout | null = null;
  private pendingChangedFiles = new Set<string>();
  private fullScanNeeded = false;
  private isFallbackMode = false;
  private activeScanPromise: Promise<ScanSummary> | null = null;

  public lastSummary: ScanSummary | null = null;
  public lastFormattedOutput: string | null = null;

  constructor(
    patterns: string[] | string | WatchOptions = ".",
    options: WatchOptions = {},
  ) {
    if (typeof patterns === "object" && !Array.isArray(patterns)) {
      this.patterns = ["."];
      this.options = { ...patterns };
    } else {
      this.patterns = Array.isArray(patterns) ? patterns : [patterns];
      this.options = { ...options };
    }
  }

  /**
   * Whether the watcher is currently active.
   */
  get isRunning(): boolean {
    return this.isWatching;
  }

  /**
   * Starts watching files and runs an initial scan.
   */
  async start(): Promise<void> {
    if (this.isWatching) {
      return;
    }
    this.isWatching = true;
    this.setupWatchers();
    await this.trigger();
  }

  /**
   * Stops watching files and cancels any pending debounce timers.
   */
  stop(): void {
    if (!this.isWatching) {
      return;
    }
    this.isWatching = false;

    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }

    for (const watcher of this.fsWatchers) {
      try {
        watcher.close();
      } catch {
        // Ignore close errors
      }
    }
    this.fsWatchers = [];
    this.watchedDirs.clear();
    this.pendingChangedFiles.clear();
    this.fullScanNeeded = false;
  }

  /**
   * Manually trigger a scan immediately, bypassing active debounce timers.
   * Can optionally target specific file paths to scan incrementally.
   */
  async trigger(changedPaths?: string[] | string): Promise<ScanSummary> {
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
    return this.queueScan(() => this.executeScan(changedPaths));
  }

  private setupWatchers(): void {
    const rootDir = this.options.cwd ? path.resolve(this.options.cwd) : process.cwd();
    const dirsToWatch = new Set<string>();

    for (const rawPattern of this.patterns) {
      const cleanPattern = rawPattern.replace(/^(\.\/|\.\\)+/, "");
      const resolvedPath = path.resolve(rootDir, cleanPattern);

      if (/[*?]/.test(cleanPattern)) {
        // Glob pattern
        const firstWildcard = cleanPattern.search(/[*?]/);
        const prefixPath = cleanPattern.slice(0, firstWildcard);
        const lastSlash = prefixPath.lastIndexOf("/");
        const baseSubdir = lastSlash !== -1 ? prefixPath.slice(0, lastSlash) : "";
        const searchRoot = path.resolve(rootDir, baseSubdir);
        let targetDir = searchRoot;
        while (!fs.existsSync(targetDir) && targetDir !== path.dirname(targetDir)) {
          targetDir = path.dirname(targetDir);
        }
        if (fs.existsSync(targetDir)) {
          dirsToWatch.add(targetDir);
        }
      } else {
        let targetPath = resolvedPath;
        if (!fs.existsSync(targetPath)) {
          while (!fs.existsSync(targetPath) && targetPath !== path.dirname(targetPath)) {
            targetPath = path.dirname(targetPath);
          }
        }
        if (fs.existsSync(targetPath)) {
          const stat = fs.statSync(targetPath);
          if (stat.isDirectory()) {
            dirsToWatch.add(targetPath);
          } else if (stat.isFile()) {
            dirsToWatch.add(path.dirname(targetPath));
          }
        }
      }
    }

    if (dirsToWatch.size === 0) {
      dirsToWatch.add(rootDir);
    }

    for (const dir of dirsToWatch) {
      this.watchDirectory(dir, rootDir);
    }
  }

  private watchDirectory(dirPath: string, rootDir: string): void {
    if (this.watchedDirs.has(dirPath)) {
      return;
    }
    this.watchedDirs.add(dirPath);

    try {
      const watcher = fs.watch(
        dirPath,
        { recursive: true },
        (eventType, filename) => {
          this.handleFsEvent(eventType, filename, dirPath, rootDir);
        },
      );
      watcher.on("error", () => {});
      this.fsWatchers.push(watcher);
    } catch {
      this.isFallbackMode = true;
      try {
        const watcher = fs.watch(
          dirPath,
          { recursive: false },
          (eventType, filename) => {
            this.handleFsEvent(eventType, filename, dirPath, rootDir);
          },
        );
        watcher.on("error", () => {});
        this.fsWatchers.push(watcher);
        this.watchSubdirectoriesFallback(dirPath, rootDir);
      } catch {
        // Ignore unwatchable directory
      }
    }
  }

  private watchSubdirectoriesFallback(parentDir: string, rootDir: string): void {
    try {
      const entries = fs.readdirSync(parentDir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory() && !IGNORED_DIRS.has(entry.name)) {
          const sub = path.join(parentDir, entry.name);
          this.watchDirectory(sub, rootDir);
        }
      }
    } catch {
      // Ignore readdir errors
    }
  }

  private handleFsEvent(
    _eventType: string,
    filename: string | null,
    dirPath: string,
    rootDir: string,
  ): void {
    if (!this.isWatching) {
      return;
    }

    if (!filename) {
      this.fullScanNeeded = true;
      this.scheduleDebounce();
      return;
    }

    const normalizedFilename = filename.replace(/\\/g, "/");
    const segments = normalizedFilename.split("/");
    if (segments.some((seg) => IGNORED_DIRS.has(seg))) {
      return;
    }

    const absPath = path.resolve(dirPath, filename);
    const displayPath = toDisplayPath(rootDir, absPath);
    const alreadyKnown = this.lastSummary?.fileResults.has(displayPath) ?? false;

    if (fs.existsSync(absPath)) {
      try {
        const stat = fs.statSync(absPath);
        if (stat.isDirectory()) {
          if (this.isFallbackMode) {
            this.watchDirectory(absPath, rootDir);
          }
          return;
        }
      } catch {
        // Ignore stat error
      }
    }

    if (!fs.existsSync(absPath)) {
      let matchedTracked = false;
      if (this.lastSummary) {
        for (const key of this.lastSummary.fileResults.keys()) {
          if (key === displayPath || key.startsWith(displayPath + "/")) {
            matchedTracked = true;
            break;
          }
        }
      }
      if (matchedTracked || isCandidateFile(absPath, this.patterns, rootDir, alreadyKnown)) {
        this.pendingChangedFiles.add(absPath);
        this.scheduleDebounce();
      }
      return;
    }

    if (isCandidateFile(absPath, this.patterns, rootDir, alreadyKnown)) {
      this.pendingChangedFiles.add(absPath);
      this.scheduleDebounce();
    }
  }

  private scheduleDebounce(): void {
    const debounceMs = this.options.debounceMs ?? 150;
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
    }
    this.debounceTimer = setTimeout(async () => {
      this.debounceTimer = null;
      if (!this.isWatching) return;
      try {
        await this.queueScan(() => this.executeScan());
      } catch (err) {
        if (!this.options.silent) {
          console.error("AgentGuardWatcher scan error:", err);
        }
      }
    }, debounceMs);
  }

  private async queueScan<T>(scanFn: () => Promise<T>): Promise<T> {
    while (this.activeScanPromise) {
      try {
        await this.activeScanPromise;
      } catch {
        // Ignore previous scan errors
      }
    }

    const promise = scanFn();
    this.activeScanPromise = promise as unknown as Promise<ScanSummary>;
    try {
      return await promise;
    } finally {
      this.activeScanPromise = null;
    }
  }

  private async executeScan(changedPaths?: string[] | string): Promise<ScanSummary> {
    const rootDir = this.options.cwd ? path.resolve(this.options.cwd) : process.cwd();

    const shouldDoFullScan =
      !this.lastSummary ||
      this.fullScanNeeded ||
      (changedPaths === undefined && this.pendingChangedFiles.size === 0);

    if (shouldDoFullScan) {
      this.pendingChangedFiles.clear();
      this.fullScanNeeded = false;
      const summary = await scanFiles(this.patterns, this.options);
      this.lastSummary = summary;
      return this.postProcessScan(summary);
    }

    // Incremental scan
    const targets = new Set<string>();
    if (changedPaths) {
      const list = Array.isArray(changedPaths) ? changedPaths : [changedPaths];
      for (const p of list) {
        targets.add(path.resolve(rootDir, p));
      }
    }
    for (const p of this.pendingChangedFiles) {
      targets.add(p);
    }
    this.pendingChangedFiles.clear();
    this.fullScanNeeded = false;

    const currentSummary = this.lastSummary!;

    for (const absPath of targets) {
      const display = toDisplayPath(rootDir, absPath);

      if (!fs.existsSync(absPath)) {
        // Path removed
        for (const key of Array.from(currentSummary.fileResults.keys())) {
          if (key === display || key.startsWith(display + "/")) {
            currentSummary.fileResults.delete(key);
          }
        }
        continue;
      }

      try {
        const stat = fs.statSync(absPath);
        if (stat.isDirectory()) {
          const dirSummary = await scanFiles(absPath, this.options);
          for (const [k, v] of dirSummary.fileResults.entries()) {
            currentSummary.fileResults.set(k, v);
          }
        } else if (stat.isFile()) {
          const fileSummary = await scanFiles(absPath, this.options);
          for (const [k, v] of fileSummary.fileResults.entries()) {
            currentSummary.fileResults.set(k, v);
          }
        }
      } catch {
        currentSummary.fileResults.delete(display);
      }
    }

    // Re-aggregate summary
    let totalFindings = 0;
    const allFindings: FileFinding[] = [];
    for (const res of currentSummary.fileResults.values()) {
      totalFindings += res.findings.length;
      allFindings.push(...res.findings);
    }

    const summaryOk = this.options.failOn
      ? !exceeds({ ok: false, findings: allFindings }, this.options.failOn)
      : allFindings.length === 0;

    const updatedSummary: ScanSummary = {
      filesScanned: currentSummary.fileResults.size,
      totalFindings,
      fileResults: currentSummary.fileResults,
      ok: summaryOk,
    };

    this.lastSummary = updatedSummary;
    return this.postProcessScan(updatedSummary);
  }

  private postProcessScan(summary: ScanSummary): ScanSummary {
    if (this.options.clearTerminal) {
      try {
        console.clear();
      } catch {
        process.stdout.write("\x1Bc");
      }
    }

    const formatted = formatScanSummaryTerminal(summary, {
      colors: this.options.colors,
    });
    this.lastFormattedOutput = formatted;

    if (!this.options.silent) {
      console.log(formatted);
    }

    if (this.options.onScanComplete) {
      this.options.onScanComplete(summary);
    }

    return summary;
  }
}

/**
 * Convenience helper to create and start an AgentGuardWatcher.
 */
export async function watchFiles(
  patterns: string[] | string = ".",
  options: WatchOptions = {},
): Promise<AgentGuardWatcher> {
  const watcher = new AgentGuardWatcher(patterns, options);
  await watcher.start();
  return watcher;
}
