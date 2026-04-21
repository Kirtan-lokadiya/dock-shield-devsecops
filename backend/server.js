const express = require("express");
const cors = require("cors");
const { execFile } = require("child_process");
const util = require("util");

const execFileAsync = util.promisify(execFile);
const app = express();
const registryCredentials = new Map();
const scanHistory = [];
const debianTrackerCache = new Map();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;

// ──────────────────────────────────────
// Health Check
// ──────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({ status: "ok", scanner: "trivy", version: "1.0.0" });
});

function normalizeRegistryHost(registry) {
  if (!registry) return "index.docker.io";

  try {
    const withScheme = registry.includes("://") ? registry : `https://${registry}`;
    return new URL(withScheme).host.toLowerCase();
  } catch (err) {
    return registry.replace(/^https?:\/\//, "").split("/")[0].toLowerCase();
  }
}

function registryHostFromImage(image) {
  const firstPart = image.split("/")[0];
  if (firstPart.includes(".") || firstPart.includes(":") || firstPart === "localhost") {
    return firstPart.toLowerCase();
  }
  return "index.docker.io";
}

function validImageName(image) {
  return /^[a-zA-Z0-9][a-zA-Z0-9._/@:-]*$/.test(image);
}

function validTag(tag) {
  return /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(tag);
}

function decodeHtmlEntities(value) {
  return String(value || "")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}

function stripHtml(value) {
  return decodeHtmlEntities(String(value || "").replace(/<br\s*\/?>/gi, "\n").replace(/<[^>]+>/g, " "))
    .replace(/\s+/g, " ")
    .trim();
}

function stripHtmlPreserveLines(value) {
  return decodeHtmlEntities(String(value || "").replace(/<br\s*\/?>/gi, "\n").replace(/<[^>]+>/g, ""))
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .join("\n");
}

function normalizePackageToken(value) {
  return String(value || "").toLowerCase().replace(/:.*$/, "").trim();
}

function isDockerHubRegistry(registryHost) {
  return ["docker.io", "index.docker.io", "registry-1.docker.io"].includes(registryHost);
}

function buildAuthArgs(image) {
  const registryHost = registryHostFromImage(image);
  const creds = registryCredentials.get(registryHost);

  if (!creds) return [];
  return ["--username", creds.username, "--password", creds.password];
}

async function validateDockerHubCredentials(username, password) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const response = await fetch("https://hub.docker.com/v2/users/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
      signal: controller.signal,
    });

    let payload = {};
    try {
      payload = await response.json();
    } catch (err) {
      payload = {};
    }

    if (!response.ok || !payload.token) {
      return {
        valid: false,
        message: payload.detail || payload.message || "Invalid Docker Hub username or token",
      };
    }

    return { valid: true };
  } catch (err) {
    return {
      valid: false,
      message: err.name === "AbortError"
        ? "Docker Hub login timed out. Try again."
        : "Could not reach Docker Hub to validate credentials.",
    };
  } finally {
    clearTimeout(timeout);
  }
}

function detectDebianRelease(osMetadata) {
  const raw = [
    osMetadata?.PrettyName,
    osMetadata?.Name,
    osMetadata?.Version,
    osMetadata?.Family,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  if (!raw.includes("debian")) return null;

  const releaseMap = [
    { suite: "sid", patterns: [" sid", " unstable"] },
    { suite: "forky", patterns: ["forky", "14"] },
    { suite: "trixie", patterns: ["trixie", "13"] },
    { suite: "bookworm", patterns: ["bookworm", "12"] },
    { suite: "bullseye", patterns: ["bullseye", "11"] },
  ];

  for (const candidate of releaseMap) {
    if (candidate.patterns.some((pattern) => raw.includes(pattern))) {
      return candidate.suite;
    }
  }

  return null;
}

function extractMetadata(vulnData) {
  const metadata = vulnData?.Metadata || {};
  const osMetadata = metadata?.OS || {};
  const osName = osMetadata?.Name || osMetadata?.Family || "linux";
  const arch = metadata?.ImageConfig?.architecture || "amd64";
  const layers = Array.isArray(metadata?.ImageConfig?.rootfs?.diff_ids)
    ? metadata.ImageConfig.rootfs.diff_ids.length
    : 0;
  const distroFamily = normalizePackageToken(osMetadata?.Family || osMetadata?.Name || "");
  const distroRelease = distroFamily === "debian" ? detectDebianRelease(osMetadata) : null;

  return {
    os: `${osName}/${arch}`,
    size: 0,
    layers,
    distroFamily,
    distroRelease,
    distroName: osName,
  };
}

function parseDebianTrackerTableRows(tableHtml, expectedColumns) {
  const rows = [];
  const matches = tableHtml.matchAll(/<tr>([\s\S]*?)<\/tr>/gi);

  for (const match of matches) {
    const cells = Array.from(match[1].matchAll(/<t[dh][^>]*>([\s\S]*?)<\/t[dh]>/gi)).map((cell) => stripHtml(cell[1]));
    if (cells.length === expectedColumns) {
      rows.push(cells);
    }
  }

  return rows;
}

function parseDebianTracker(html) {
  const vulnerableTableMatch = html.match(/<h2>Vulnerable and fixed packages<\/h2>[\s\S]*?<table>([\s\S]*?)<\/table>/i);
  const fixedTableMatch = html.match(/The information below is based on the following data on fixed versions\.<\/p><table>([\s\S]*?)<\/table>/i);
  const notesMatch = html.match(/<h2>Notes<\/h2><pre>([\s\S]*?)<\/pre>/i);

  const vulnerableRows = vulnerableTableMatch ? parseDebianTrackerTableRows(vulnerableTableMatch[1], 4) : [];
  const fixedRows = fixedTableMatch ? parseDebianTrackerTableRows(fixedTableMatch[1], 7) : [];

  let currentSourcePackage = "";
  const packageStatus = [];
  for (const [sourceCell, release, version, status] of vulnerableRows) {
    if (sourceCell && sourceCell !== "Source Package") {
      currentSourcePackage = sourceCell.split(" (")[0].trim();
    }
    if (!currentSourcePackage || release === "Release") continue;
    packageStatus.push({
      sourcePackage: currentSourcePackage,
      release,
      version,
      status,
    });
  }

  const fixedVersions = [];
  for (const [pkg, type, release, fixedVersion] of fixedRows) {
    if (!pkg || pkg === "Package") continue;
    fixedVersions.push({
      package: pkg,
      type,
      release,
      fixedVersion,
    });
  }

  const notesText = notesMatch ? stripHtmlPreserveLines(notesMatch[1]) : "";
  const notes = notesText
    .split("\n")
    .map((line) => {
      const match = line.match(/^\[([^\]]+)\]\s*-\s*([^\s]+)\s+<([^>]+)>\s*(?:\(([^)]+)\))?/);
      if (!match) return null;
      return {
        release: match[1].trim().toLowerCase(),
        package: normalizePackageToken(match[2]),
        tag: match[3].trim(),
        detail: (match[4] || "").trim(),
      };
    })
    .filter(Boolean);

  const upstreamFixedVersion = notesText.match(/Fixed by:\s+\S+\s+\(([^)]+)\)/i)?.[1] || "";

  return {
    packageStatus,
    fixedVersions,
    notes,
    notesText,
    upstreamFixedVersion,
  };
}

async function fetchDebianTracker(cveId) {
  if (debianTrackerCache.has(cveId)) {
    return debianTrackerCache.get(cveId);
  }

  try {
    const response = await fetch(`https://security-tracker.debian.org/tracker/${encodeURIComponent(cveId)}`);
    if (!response.ok) {
      debianTrackerCache.set(cveId, null);
      return null;
    }

    const html = await response.text();
    const parsed = parseDebianTracker(html);
    debianTrackerCache.set(cveId, parsed);
    return parsed;
  } catch (err) {
    debianTrackerCache.set(cveId, null);
    return null;
  }
}

function pickDebianSourcePackage(tracker, packageName) {
  const knownPackages = Array.from(
    new Set(tracker.packageStatus.map((item) => normalizePackageToken(item.sourcePackage)).filter(Boolean))
  );

  if (!knownPackages.length) return null;

  const normalizedPackage = normalizePackageToken(packageName);
  const directMatch = knownPackages.find(
    (candidate) =>
      candidate === normalizedPackage ||
      normalizedPackage.startsWith(`${candidate}-`) ||
      candidate.startsWith(`${normalizedPackage}-`)
  );

  if (directMatch) return directMatch;
  if (knownPackages.length === 1) return knownPackages[0];
  return null;
}

function selectDebianReleaseRow(rows, release) {
  if (!release) return null;

  const normalizedRelease = release.toLowerCase();
  return (
    rows.find((row) => row.release.toLowerCase() === normalizedRelease) ||
    rows.find((row) => row.release.toLowerCase().startsWith(`${normalizedRelease} (`)) ||
    null
  );
}

function buildFallbackFixInfo(vuln, metadata) {
  const distroLabel = metadata.distroRelease
    ? `${metadata.distroFamily} ${metadata.distroRelease}`
    : metadata.distroName || metadata.os;

  if (vuln.fixed_version && vuln.fixed_version !== "No fix available") {
    return {
      fixed_version: vuln.fixed_version,
      fix_label: vuln.fixed_version,
      fix_guidance: `Upgrade ${vuln.package} to ${vuln.fixed_version}.`,
      advisory_url: vuln.primary_url || "",
      advisory_source: "Scanner advisory",
    };
  }

  return {
    fixed_version: "Vendor fix pending",
    fix_label: "Vendor fix pending",
    fix_guidance: `No patched package is published yet for ${distroLabel}. Monitor the vendor advisory and rebuild when a fixed package becomes available.`,
    advisory_url: vuln.primary_url || "",
    advisory_source: "Scanner advisory",
  };
}

function buildDebianFixInfo(vuln, metadata, tracker, fallback) {
  const sourcePackage = pickDebianSourcePackage(tracker, vuln.package);
  if (!sourcePackage) {
    return fallback;
  }

  const suite = metadata.distroRelease;
  const suiteLabel = suite ? `Debian ${suite}` : "the detected Debian release";
  const packageRows = tracker.packageStatus.filter(
    (row) => normalizePackageToken(row.sourcePackage) === sourcePackage
  );
  const fixedRows = tracker.fixedVersions.filter(
    (row) => normalizePackageToken(row.package) === sourcePackage
  );
  const suiteRow = selectDebianReleaseRow(packageRows, suite);
  const suiteNote = tracker.notes.find(
    (note) => note.release === suite && note.package === sourcePackage
  );
  const nearestFixed = fixedRows.find((row) => row.release !== "(unstable)") || fixedRows[0] || null;
  const noteText = suiteNote
    ? ` Debian marks this as ${suiteNote.tag}${suiteNote.detail ? ` (${suiteNote.detail})` : ""}.`
    : "";

  if (fallback.fix_label !== "Vendor fix pending") {
    return {
      ...fallback,
      fix_guidance: `Upgrade ${vuln.package} to ${fallback.fix_label}.`,
      advisory_url: `https://security-tracker.debian.org/tracker/${encodeURIComponent(vuln.id)}`,
      advisory_source: "Debian Security Tracker",
    };
  }

  if (suiteRow && suiteRow.status.toLowerCase() === "fixed") {
    return {
      fixed_version: suiteRow.version,
      fix_label: suiteRow.version,
      fix_guidance: `Upgrade ${sourcePackage} in ${suiteLabel} to ${suiteRow.version}.`,
      advisory_url: `https://security-tracker.debian.org/tracker/${encodeURIComponent(vuln.id)}`,
      advisory_source: "Debian Security Tracker",
    };
  }

  if (suiteRow && suiteRow.status.toLowerCase() === "vulnerable") {
    const prefix = nearestFixed
      ? `${suiteLabel} still ships a vulnerable package. The nearest Debian fix listed is ${nearestFixed.release} ${nearestFixed.fixedVersion}.`
      : `${suiteLabel} still ships a vulnerable package.`;
    const upstream = tracker.upstreamFixedVersion
      ? ` Upstream fixed this in ${tracker.upstreamFixedVersion}.`
      : "";

    return {
      fixed_version: `${suiteLabel} package still vulnerable`,
      fix_label: `${suiteLabel} package still vulnerable`,
      fix_guidance: `${prefix}${upstream} Rebuild when Debian publishes a ${suite} package update or move to a newer compatible base image.${noteText}`,
      advisory_url: `https://security-tracker.debian.org/tracker/${encodeURIComponent(vuln.id)}`,
      advisory_source: "Debian Security Tracker",
    };
  }

  if (nearestFixed) {
    return {
      fixed_version: nearestFixed.fixedVersion,
      fix_label: nearestFixed.fixedVersion,
      fix_guidance: `A fixed Debian package is listed as ${nearestFixed.release} ${nearestFixed.fixedVersion}. Rebuild against a base image that contains that package or a newer compatible release.`,
      advisory_url: `https://security-tracker.debian.org/tracker/${encodeURIComponent(vuln.id)}`,
      advisory_source: "Debian Security Tracker",
    };
  }

  return {
    ...fallback,
    advisory_url: `https://security-tracker.debian.org/tracker/${encodeURIComponent(vuln.id)}`,
    advisory_source: "Debian Security Tracker",
  };
}

async function enrichFixGuidance(vulnerabilities, metadata) {
  return Promise.all(
    vulnerabilities.map(async (vuln) => {
      const fallback = buildFallbackFixInfo(vuln, metadata);
      if (metadata.distroFamily !== "debian" || !/^CVE-\d{4}-\d+$/i.test(vuln.id)) {
        return { ...vuln, ...fallback };
      }

      const tracker = await fetchDebianTracker(vuln.id);
      if (!tracker) {
        return { ...vuln, ...fallback };
      }

      return {
        ...vuln,
        ...buildDebianFixInfo(vuln, metadata, tracker, fallback),
      };
    })
  );
}

// ──────────────────────────────────────
// Docker Registry Login
// ──────────────────────────────────────
app.post("/api/auth/login", async (req, res) => {
  const { registry, username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: "Username and password are required",
    });
  }

  const registryHost = normalizeRegistryHost(registry);

  if (!isDockerHubRegistry(registryHost)) {
    return res.status(400).json({
      success: false,
      message: `Credential validation is currently supported for Docker Hub only. Use Docker Hub or validate ${registryHost} during scan.`,
    });
  }

  const validation = await validateDockerHubCredentials(username, password);
  if (!validation.valid) {
    return res.status(401).json({
      success: false,
      message: validation.message,
    });
  }

  registryCredentials.set(registryHost, {
    username,
    password,
    savedAt: new Date().toISOString(),
  });

  return res.json({
    success: true,
    message: `Credentials saved for ${registryHost}. They will be used during scans.`,
  });
});

// ──────────────────────────────────────
// List Images (from scan history in daemonless mode)
// ──────────────────────────────────────
app.get("/api/images/local", async (req, res) => {
  const latestByImage = new Map();
  for (const item of scanHistory) {
    const key = `${item.image}:${item.tag}`;
    if (!latestByImage.has(key)) latestByImage.set(key, item);
  }

  const images = Array.from(latestByImage.values()).map((item) => ({
    name: item.image,
    tag: item.tag,
    size: `${item.size_mb || 0} MB`,
    created: new Date(item.scanned_at).toISOString().split("T")[0],
  }));

  return res.json({
    images,
    note: "Local Docker daemon image listing is unavailable in Kubernetes mode.",
  });
});

// ──────────────────────────────────────
// SCAN IMAGE - The Main Feature
// ──────────────────────────────────────
app.post("/api/scan", async (req, res) => {
  const image = (req.body.image || "").trim();
  const tag = (req.body.tag || "latest").trim();

  if (!image) {
    return res.status(400).json({ error: "Image name is required" });
  }
  if (!validImageName(image) || !validTag(tag)) {
    return res.status(400).json({
      error: "Invalid image or tag format",
      suggestion: "Use image format like nginx:latest or ghcr.io/user/app:v1",
    });
  }

  const fullImage = `${image}:${tag}`;
  const authArgs = buildAuthArgs(image);

  try {
    // Step 1: Run Trivy vulnerability scan (daemonless mode)
    console.log(`[SCAN] Running Trivy scan on: ${fullImage}`);
    const { stdout: vulnScan } = await execFileAsync(
      "trivy",
      [
        "image",
        "--format",
        "json",
        "--severity",
        "CRITICAL,HIGH,MEDIUM,LOW",
        "--timeout",
        "10m",
        ...authArgs,
        fullImage,
      ],
      { timeout: 300000, maxBuffer: 50 * 1024 * 1024 }
    );

    // Step 2: Run Trivy secret scan
    console.log(`[SCAN] Running secret detection on: ${fullImage}`);
    let secretScan = { Results: [] };
    try {
      const { stdout: secretOut } = await execFileAsync(
        "trivy",
        ["image", "--format", "json", "--scanners", "secret", "--timeout", "10m", ...authArgs, fullImage],
        { timeout: 120000, maxBuffer: 50 * 1024 * 1024 }
      );
      secretScan = JSON.parse(secretOut);
    } catch (e) {
      console.log("[SCAN] Secret scan skipped:", e.message);
    }

    // Step 3: Run Trivy misconfiguration scan
    console.log(`[SCAN] Running misconfig check on: ${fullImage}`);
    let misconfigScan = { Results: [] };
    try {
      const { stdout: misconfigOut } = await execFileAsync(
        "trivy",
        ["image", "--format", "json", "--scanners", "misconfig", "--timeout", "10m", ...authArgs, fullImage],
        { timeout: 120000, maxBuffer: 50 * 1024 * 1024 }
      );
      misconfigScan = JSON.parse(misconfigOut);
    } catch (e) {
      console.log("[SCAN] Misconfig scan skipped:", e.message);
    }

    // Step 4: Parse and format results
    const vulnData = JSON.parse(vulnScan);
    const metadata = extractMetadata(vulnData);
    const report = await formatScanReport(image, tag, vulnData, secretScan, misconfigScan, metadata);
    scanHistory.unshift(report);
    if (scanHistory.length > 100) scanHistory.pop();

    console.log(`[SCAN] Complete: ${fullImage} - Score: ${report.score}`);
    res.json(report);
  } catch (err) {
    const details = err.stderr || err.message;
    console.error(`[SCAN] Failed: ${fullImage}`, details);
    res.status(500).json({
      error: "Scan failed",
      details,
      suggestion: details.includes("UNAUTHORIZED") || details.includes("authentication")
        ? "Authentication failed. Reconnect with valid registry credentials."
        : details.includes("not found")
        ? "Image not found. Check the image name or login to the registry first."
        : details.includes("timeout")
        ? "Scan timed out. The image may be very large."
        : "An unexpected error occurred during scanning.",
    });
  }
});

// ──────────────────────────────────────
// Format Scan Report
// ──────────────────────────────────────
async function formatScanReport(image, tag, vulnData, secretData, misconfigData, metadata) {
  // Extract vulnerabilities
  const vulnerabilities = [];
  const summary = { critical: 0, high: 0, medium: 0, low: 0 };

  if (vulnData.Results) {
    for (const result of vulnData.Results) {
      if (result.Vulnerabilities) {
        for (const vuln of result.Vulnerabilities) {
          const sev = (vuln.Severity || "UNKNOWN").toUpperCase();
          if (summary[sev.toLowerCase()] !== undefined) {
            summary[sev.toLowerCase()]++;
          }
          vulnerabilities.push({
            id: vuln.VulnerabilityID,
            package: vuln.PkgName,
            installed_version: vuln.InstalledVersion,
            fixed_version: vuln.FixedVersion || "No fix available",
            severity: sev,
            title: vuln.Title || vuln.Description?.substring(0, 120) || "No description",
            cvss: vuln.CVSS?.nvd?.V3Score || vuln.CVSS?.redhat?.V3Score || 0,
            primary_url: vuln.PrimaryURL || vuln.DataSource?.URL || "",
          });
        }
      }
    }
  }

  // Extract secrets
  const secrets = [];
  if (secretData.Results) {
    for (const result of secretData.Results) {
      if (result.Secrets) {
        for (const secret of result.Secrets) {
          secrets.push({
            type: secret.RuleID || secret.Category || "Unknown Secret",
            file: secret.Target || result.Target,
            line: secret.StartLine || 0,
          });
        }
      }
    }
  }

  // Extract misconfigurations
  const misconfigurations = [];
  if (misconfigData.Results) {
    for (const result of misconfigData.Results) {
      if (result.Misconfigurations) {
        for (const mc of result.Misconfigurations) {
          misconfigurations.push({
            check: mc.Title || mc.ID,
            status: mc.Status === "PASS" ? "PASS" : mc.Severity === "LOW" ? "WARN" : "FAIL",
            severity: mc.Severity || "MEDIUM",
          });
        }
      }
    }
  }

  // Calculate security score
  const score = calculateScore(summary, secrets.length, misconfigurations);
  const visibleVulnerabilities = vulnerabilities
    .sort((a, b) => {
      const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
      return (order[a.severity] || 4) - (order[b.severity] || 4);
    })
    .slice(0, 50);
  const enrichedVulnerabilities = await enrichFixGuidance(visibleVulnerabilities, metadata);

  return {
    image,
    tag,
    os: metadata.os || "linux/amd64",
    size_mb: Math.round((metadata.size || 0) / 1024 / 1024),
    layers: metadata.layers || 0,
    score,
    summary,
    vulnerabilities: enrichedVulnerabilities,
    secrets,
    misconfigurations,
    scanned_at: new Date().toISOString(),
  };
}

function calculateScore(summary, secretCount, misconfigs) {
  let score = 100;
  score -= summary.critical * 15;
  score -= summary.high * 5;
  score -= summary.medium * 2;
  score -= summary.low * 0.5;
  score -= secretCount * 10;
  score -= misconfigs.filter((m) => m.status === "FAIL").length * 5;
  return Math.max(0, Math.min(100, Math.round(score)));
}

// ──────────────────────────────────────
// Scan History (in-memory for simplicity)
// ──────────────────────────────────────
app.get("/api/history", (req, res) => {
  res.json({ scans: scanHistory });
});

// ──────────────────────────────────────
// Start Server
// ──────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
  ╔══════════════════════════════════════╗
  ║   🛡️  DOCK SHIELD SCANNER API       ║
  ║   Running on port ${PORT}              ║
  ║   Ready to scan Docker images        ║
  ╚══════════════════════════════════════╝
  `);
});
