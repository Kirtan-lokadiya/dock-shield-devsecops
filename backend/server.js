const express = require("express");
const cors = require("cors");
const { execFile } = require("child_process");
const util = require("util");

const execFileAsync = util.promisify(execFile);
const app = express();
const registryCredentials = new Map();
const scanHistory = [];

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

function extractMetadata(vulnData) {
  const metadata = vulnData?.Metadata || {};
  const osName = metadata?.OS?.Name || metadata?.OS?.Family || "linux";
  const arch = metadata?.ImageConfig?.architecture || "amd64";
  const layers = Array.isArray(metadata?.ImageConfig?.rootfs?.diff_ids)
    ? metadata.ImageConfig.rootfs.diff_ids.length
    : 0;

  return {
    os: `${osName}/${arch}`,
    size: 0,
    layers,
  };
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
    const report = formatScanReport(image, tag, vulnData, secretScan, misconfigScan, metadata);
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
function formatScanReport(image, tag, vulnData, secretData, misconfigData, metadata) {
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

  return {
    image,
    tag,
    os: metadata.os || "linux/amd64",
    size_mb: Math.round((metadata.size || 0) / 1024 / 1024),
    layers: metadata.layers || 0,
    score,
    summary,
    vulnerabilities: vulnerabilities
      .sort((a, b) => {
        const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
        return (order[a.severity] || 4) - (order[b.severity] || 4);
      })
      .slice(0, 50), // Top 50 vulns
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
