# Instanton Kubernetes Deployment

Deploy Instanton relay server to Kubernetes.

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
  INSTANTON_DOMAIN: "tunnel.yourdomain.com"
```

### 2. Add TLS Certificates

Option A: Manual certificate

```bash
# Create secret from files
kubectl create secret tls instanton-tls \
  --cert=cert.pem \
  --key=key.pem \
  -n instanton
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
kubectl get pods -n instanton

# Check services
kubectl get svc -n instanton

# View logs
kubectl logs -f deployment/instanton-server -n instanton

# Test health
kubectl port-forward svc/instanton-control 8443:8443 -n instanton
curl http://localhost:8443/health
```

## Scaling

Manual scaling:

```bash
kubectl scale deployment instanton-server --replicas=5 -n instanton
```

Auto-scaling is configured via `hpa.yaml` (2-10 replicas based on CPU/memory).

## Monitoring

The deployment exposes Prometheus metrics on port 9090.

Add to your Prometheus config:

```yaml
- job_name: 'instanton'
  kubernetes_sd_configs:
    - role: pod
      namespaces:
        names: ['instanton']
  relabel_configs:
    - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
      action: keep
      regex: true
```

## Troubleshooting

### Pods not starting

```bash
kubectl describe pod -n instanton
kubectl logs -n instanton <pod-name>
```

### Connection refused

Check if services are running:

```bash
kubectl get endpoints -n instanton
```

### TLS errors

Verify certificate:

```bash
kubectl get secret instanton-tls -n instanton -o yaml
```
