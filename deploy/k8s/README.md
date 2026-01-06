# Tachyon Kubernetes Deployment

Deploy Tachyon relay server to Kubernetes.

## Quick Start

```bash
# Create namespace and deploy
kubectl apply -f namespace.yaml
kubectl apply -f configmap.yaml
kubectl apply -f secret.yaml
kubectl apply -f serviceaccount.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml

# Optional: Ingress, HPA, PDB
kubectl apply -f ingress.yaml
kubectl apply -f hpa.yaml
kubectl apply -f pdb.yaml
```

## Or all at once

```bash
kubectl apply -f .
```

## Configuration

### 1. Update Domain

Edit `configmap.yaml`:

```yaml
data:
  TACHYON_DOMAIN: "tunnel.yourdomain.com"
```

### 2. Add TLS Certificates

Option A: Manual certificate

```bash
# Create secret from files
kubectl create secret tls tachyon-tls \
  --cert=cert.pem \
  --key=key.pem \
  -n tachyon
```

Option B: Using cert-manager (recommended)

```yaml
# Add to ingress.yaml annotations:
cert-manager.io/cluster-issuer: "letsencrypt-prod"
```

### 3. Update Ingress

Edit `ingress.yaml` with your domain:

```yaml
spec:
  tls:
    - hosts:
        - "*.tunnel.yourdomain.com"
```

## Verify Deployment

```bash
# Check pods
kubectl get pods -n tachyon

# Check services
kubectl get svc -n tachyon

# View logs
kubectl logs -f deployment/tachyon-server -n tachyon

# Test health
kubectl port-forward svc/tachyon-control 8443:8443 -n tachyon
curl http://localhost:8443/health
```

## Scaling

Manual scaling:

```bash
kubectl scale deployment tachyon-server --replicas=5 -n tachyon
```

Auto-scaling is configured via `hpa.yaml` (2-10 replicas based on CPU/memory).

## Monitoring

The deployment exposes Prometheus metrics on port 9090.

Add to your Prometheus config:

```yaml
- job_name: 'tachyon'
  kubernetes_sd_configs:
    - role: pod
      namespaces:
        names: ['tachyon']
  relabel_configs:
    - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
      action: keep
      regex: true
```

## Troubleshooting

### Pods not starting

```bash
kubectl describe pod -n tachyon
kubectl logs -n tachyon <pod-name>
```

### Connection refused

Check if services are running:

```bash
kubectl get endpoints -n tachyon
```

### TLS errors

Verify certificate:

```bash
kubectl get secret tachyon-tls -n tachyon -o yaml
```
