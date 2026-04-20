const express = require("express");
const cors = require("cors");
const { exec } = require("child_process");
const util = require("util");
const Docker = require("dockerode");

const execAsync = util.promisify(exec);
const app = express();
const docker = new Docker({ socketPath: "/var/run/docker.sock" });

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;

// ──────────────────────────────────────
// Health Check
// ──────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({ status: "ok", scanner: "trivy", version: "1.0.0" });
});

// ──────────────────────────────────────
// Docker Registry Login
// ──────────────────────────────────────
app.post("/api/auth/login", async (req, res) => {
  const { registry, username, password } = req.body;

  // Default to Docker Hub if no registry specified
  const registryUrl = registry || "https://index.docker.io/v1/";

  try {
    await execAsync(
      `docker login ${registryUrl} -u "${username}" -p "${password}"`
    );
    res.json({ success: true, message: "Authenticated successfully" });
  } catch (err) {
    res.status(401).json({
      success: false,
      message: "Authentication failed",
      error: err.stderr,
    });
  }
});

// ──────────────────────────────────────
// List Images (from connected registry)
// ──────────────────────────────────────
app.get("/api/images/local", async (req, res) => {
  try {
    const images = await docker.listImages();
    const formatted = images
      .filter((img) => img.RepoTags && img.RepoTags[0] !== "<none>:<none>")
      .map((img) => ({
        id: img.Id.substring(7, 19),
        name: img.RepoTags[0].split(":")[0],
        tag: img.RepoTags[0].split(":")[1] || "latest",
        size: `${Math.round(img.Size / 1024 / 1024)} MB`,
        created: new Date(img.Created * 1000).toISOString().split("T")[0],
      }));
    res.json({ images: formatted });
  } catch (err) {
    res.status(500).json({ error: "Failed to list images", details: err.message });
  }
});

// ──────────────────────────────────────
// SCAN IMAGE - The Main Feature
// ──────────────────────────────────────
app.post("/api/scan", async (req, res) => {
  const { image, tag = "latest" } = req.body;
  const fullImage = `${image}:${tag}`;

  if (!image) {
    return res.status(400).json({ error: "Image name is required" });
  }

  try {
    // Step 1: Pull the image (needed for private images)
    console.log(`[SCAN] Pulling image: ${fullImage}`);
    await execAsync(`docker pull ${fullImage}`, { timeout: 120000 });

    // Step 2: Run Trivy vulnerability scan
    console.log(`[SCAN] Running Trivy scan on: ${fullImage}`);
    const { stdout: vulnScan } = await execAsync(
      `trivy image --format json --severity CRITICAL,HIGH,MEDIUM,LOW ${fullImage}`,
      { timeout: 300000, maxBuffer: 50 * 1024 * 1024 }
    );

    // Step 3: Run Trivy secret scan
    console.log(`[SCAN] Running secret detection on: ${fullImage}`);
    let secretScan = { Results: [] };
    try {
      const { stdout: secretOut } = await execAsync(
        `trivy image --format json --scanners secret ${fullImage}`,
        { timeout: 120000, maxBuffer: 50 * 1024 * 1024 }
      );
      secretScan = JSON.parse(secretOut);
    } catch (e) {
      console.log("[SCAN] Secret scan skipped:", e.message);
    }

    // Step 4: Run Trivy misconfiguration scan
    console.log(`[SCAN] Running misconfig check on: ${fullImage}`);
    let misconfigScan = { Results: [] };
    try {
      const { stdout: misconfigOut } = await execAsync(
        `trivy image --format json --scanners misconfig ${fullImage}`,
        { timeout: 120000, maxBuffer: 50 * 1024 * 1024 }
      );
      misconfigScan = JSON.parse(misconfigOut);
    } catch (e) {
      console.log("[SCAN] Misconfig scan skipped:", e.message);
    }

    // Step 5: Get image metadata
    const { stdout: inspectOut } = await execAsync(
      `docker inspect ${fullImage} --format '{"size":{{.Size}},"layers":{{len .RootFS.Layers}},"os":"{{.Os}}/{{.Architecture}}"}'`
    );
    const metadata = JSON.parse(inspectOut);

    // Step 6: Parse and format results
    const vulnData = JSON.parse(vulnScan);
    const report = formatScanReport(fullImage, image, tag, vulnData, secretScan, misconfigScan, metadata);

    console.log(`[SCAN] Complete: ${fullImage} - Score: ${report.score}`);
    res.json(report);
  } catch (err) {
    console.error(`[SCAN] Failed: ${fullImage}`, err.message);
    res.status(500).json({
      error: "Scan failed",
      details: err.message,
      suggestion: err.message.includes("not found")
        ? "Image not found. Check the image name or login to the registry first."
        : err.message.includes("timeout")
        ? "Scan timed out. The image may be very large."
        : "An unexpected error occurred during scanning.",
    });
  }
});

// ──────────────────────────────────────
// Format Scan Report
// ──────────────────────────────────────
function formatScanReport(fullImage, image, tag, vulnData, secretData, misconfigData, metadata) {
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
const scanHistory = [];

app.get("/api/history", (req, res) => {
  res.json({ scans: scanHistory });
});

// Wrap the scan endpoint to save history
const originalScanHandler = app._router.stack.find(
  (r) => r.route && r.route.path === "/api/scan" && r.route.methods.post
);

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
