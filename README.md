# 🛡️ Dock Shield - Docker Security Scanner Dashboard

A full-stack DevSecOps project that scans **any Docker image** (public or private) for vulnerabilities, secrets, and misconfigurations — powered by **Trivy**, deployed with **Docker**, **Kubernetes**, **Terraform**, and **GitHub Actions**.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    GITHUB ACTIONS                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │ Gitleaks │  │ Semgrep  │  │  Trivy   │  │ Deploy  │ │
│  │ (secrets)│  │ (SAST)   │  │ (images) │  │ (k8s)   │ │
│  └──────────┘  └──────────┘  └──────────┘  └─────────┘ │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                KUBERNETES (DigitalOcean)                  │
│                                                          │
│  ┌──────────────────┐     ┌──────────────────────────┐  │
│  │   Frontend (UI)  │────▶│   Backend API            │  │
│  │   nginx:alpine   │     │   Node.js + Trivy        │  │
│  │   Port 80        │     │   Port 4000              │  │
│  └──────────────────┘     │                          │  │
│                           │  ┌─────────────────────┐ │  │
│                           │  │ Trivy Scanner        │ │  │
│                           │  │ - Vuln scanning      │ │  │
│                           │  │ - Secret detection   │ │  │
│                           │  │ - Misconfig checks   │ │  │
│                           │  └─────────────────────┘ │  │
│                           │                          │  │
│                           │  Docker Socket Mount ──────────▶ Pull & Scan
│                           └──────────────────────────┘  │    Any Image
│                                                          │
│  Provisioned by: TERRAFORM                               │
└─────────────────────────────────────────────────────────┘
```

## 📁 Project Structure

```
dock-shield/
├── backend/
│   ├── server.js          # Express API with Trivy integration
│   ├── package.json
│   └── Dockerfile         # Node.js + Trivy scanner
├── frontend/
│   ├── index.html         # Dashboard UI
│   └── Dockerfile         # nginx static server
├── k8s/
│   └── deployment.yaml    # K8s manifests (Deployments, Services)
├── terraform/
│   └── main.tf            # DigitalOcean infra (K8s cluster, registry)
├── .github/workflows/
│   └── ci-cd.yml          # Full DevSecOps pipeline
├── docker-compose.yml     # Local development stack
└── README.md
```

## 🚀 Quick Start (Local Development)

### Prerequisites
- Docker & Docker Compose installed
- Docker daemon running

### Step 1: Clone & Run
```bash
git clone https://github.com/YOUR_USER/dock-shield.git
cd dock-shield
docker-compose up -d
```

### Step 2: Open Dashboard
```
Frontend: http://localhost:3000
Backend:  http://localhost:4000/health
```

### Step 3: Login & Scan
1. Enter your Docker Hub credentials (or any registry)
2. Type an image name: `nginx:latest`, `python:3.10`, or your private image
3. Click SCAN and watch real Trivy results appear!

## ☁️ Deploy to DigitalOcean

### Step 1: Provision Infrastructure
```bash
cd terraform
export TF_VAR_do_token="your-digitalocean-api-token"
terraform init
terraform plan
terraform apply
```

### Step 2: Configure kubectl
```bash
# Get kubeconfig from Terraform output
terraform output -raw kubeconfig > ~/.kube/dock-shield-config
export KUBECONFIG=~/.kube/dock-shield-config
```

### Step 3: Deploy to K8s
```bash
# Update image references in k8s/deployment.yaml
kubectl apply -f k8s/
```

### Step 4: Get External IP
```bash
kubectl get svc dock-shield-ui
# Open the EXTERNAL-IP in your browser
```

## 🔒 Supported Registries

| Registry | Login Format |
|----------|-------------|
| Docker Hub | Username + Access Token |
| GitHub (ghcr.io) | GitHub username + Personal Access Token |
| AWS ECR | AWS Access Key ID + Secret Key |
| Google GCR | `_json_key` + Service Account JSON |
| Azure ACR | Service Principal ID + Password |
| Private Registry | Username + Password |

## 🔍 What Gets Scanned

| Check | Tool | What It Finds |
|-------|------|---------------|
| OS Package Vulns | Trivy | CVEs in apt/apk/yum packages |
| App Dependencies | Trivy | Vuln npm/pip/go modules |
| Embedded Secrets | Trivy | API keys, passwords, tokens in files |
| Dockerfile Issues | Trivy | Running as root, no healthcheck, etc |

## 📊 API Endpoints

```
POST /api/auth/login     - Authenticate with Docker registry
POST /api/scan           - Scan an image { image: "nginx", tag: "latest" }
GET  /api/images/local   - List locally available Docker images
GET  /api/history        - Get scan history
GET  /health             - Health check
```

## 🛠️ CI/CD Pipeline (GitHub Actions)

Every push triggers:
1. **Gitleaks** → Detect hardcoded secrets in code
2. **Semgrep** → Static code analysis (OWASP Top 10)
3. **Docker Build** → Build backend & frontend images
4. **Trivy Scan** → Scan our own images for CVEs
5. **Push to GHCR** → Push to GitHub Container Registry
6. **Deploy to K8s** → Rolling update on DigitalOcean

## 💡 Skills Demonstrated

- **Docker**: Multi-stage builds, Docker-in-Docker, socket mounting
- **Kubernetes**: Deployments, Services, LoadBalancer, health probes
- **Terraform**: IaC for DigitalOcean (K8s cluster, container registry, firewall)
- **GitHub Actions**: Multi-stage DevSecOps pipeline with security scanning
- **Security**: Trivy scanning, secret detection, SAST analysis
- **Full-Stack**: Node.js backend + vanilla JS frontend dashboard
# dock-shield-devsecops
