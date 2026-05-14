#!/usr/bin/env bash
# Install k3s and deploy the BAS Platform Helm chart.
# Run AFTER harden-ubuntu.sh and setup-postgres.sh.

set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }

POSTGRES_PASSWORD="${1:-}"
JWT_SECRET="${2:-}"

if [[ -z "$POSTGRES_PASSWORD" || -z "$JWT_SECRET" ]]; then
    echo "Usage: $0 <postgres_password> <jwt_secret>"
    exit 1
fi

info() { echo "[INFO] $*"; }

# ── Install k3s ───────────────────────────────────────────────────────────────
info "Installing k3s (lightweight Kubernetes)"
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="\
    --disable traefik \
    --disable servicelb \
    --write-kubeconfig-mode 644" sh -

# Wait for k3s to be ready
info "Waiting for k3s node to be ready"
until kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes | grep -q " Ready"; do
    sleep 3
done
info "k3s node ready"

# ── Install ingress-nginx (baremetal — no cloud load balancer needed) ─────────
info "Installing ingress-nginx"
kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply \
    -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.11.2/deploy/static/provider/baremetal/deploy.yaml

info "Waiting for ingress-nginx controller to be ready"
kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml wait \
    --namespace ingress-nginx \
    --for=condition=ready pod \
    --selector=app.kubernetes.io/component=controller \
    --timeout=120s

# Remove admission webhook — avoids Helm failures on bare-metal where
# the webhook endpoint may not be reachable during first deploy
kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml \
    delete validatingwebhookconfiguration ingress-nginx-admission 2>/dev/null || true

# ── Install Helm ──────────────────────────────────────────────────────────────
info "Installing Helm"
curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# ── Deploy BAS Platform ───────────────────────────────────────────────────────
info "Deploying BAS Platform via Helm"
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

helm upgrade --install bas-platform ./helm/bas-platform \
    --namespace bas-platform \
    --create-namespace \
    --set postgres.password="$POSTGRES_PASSWORD" \
    --set orchestrator.config.jwtSecret="$JWT_SECRET" \
    --set postgres.host="host.k3s.internal" \
    --wait --timeout 5m

info ""
info "=== BAS Platform deployed ==="
kubectl get pods -n bas-platform
info ""
info "Access the dashboard at: http://$(hostname -I | awk '{print $1}')"
info "Default credentials: admin / ChangeMe!2024"
info "CHANGE THE DEFAULT PASSWORD IMMEDIATELY."
