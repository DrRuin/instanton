# Tachyon Helm Chart

Deploy Tachyon relay server to Kubernetes using Helm.

## Prerequisites

- Kubernetes 1.23+
- Helm 3.0+
- TLS certificate for your domain

## Installation

### Quick Start

```bash
# Add the Tachyon Helm repository
helm repo add tachyon https://DrRuin.github.io/charts
helm repo update

# Install with default values
helm install tachyon tachyon/tachyon \
  --namespace tachyon \
  --create-namespace \
  --set domain=tunnel.example.com
```

### From Local Chart

```bash
cd deploy/helm
helm install tachyon ./tachyon \
  --namespace tachyon \
  --create-namespace \
  --set domain=tunnel.example.com
```

## Configuration

### Basic Configuration

```bash
helm install tachyon ./tachyon \
  --set domain=tunnel.example.com \
  --set replicaCount=3 \
  --set resources.requests.memory=256Mi
```

### With Ingress

```bash
helm install tachyon ./tachyon \
  --set domain=tunnel.example.com \
  --set ingress.enabled=true \
  --set ingress.className=nginx
```

### With cert-manager

```bash
helm install tachyon ./tachyon \
  --set domain=tunnel.example.com \
  --set ingress.enabled=true \
  --set ingress.annotations."cert-manager\.io/cluster-issuer"=letsencrypt-prod
```

### Using Existing TLS Secret

```bash
# Create secret first
kubectl create secret tls my-tls-secret \
  --cert=cert.pem \
  --key=key.pem \
  -n tachyon

# Install with existing secret
helm install tachyon ./tachyon \
  --set domain=tunnel.example.com \
  --set tls.existingSecret=my-tls-secret
```

## Values

| Parameter | Description | Default |
|-----------|-------------|---------|
| `domain` | Base domain for tunnels | `tunnel.example.com` |
| `replicaCount` | Number of replicas | `2` |
| `image.repository` | Image repository | `tachyon/tachyon-server` |
| `image.tag` | Image tag | `latest` |
| `logLevel` | Log level | `info` |
| `maxTunnels` | Maximum tunnels | `1000` |
| `service.https.type` | HTTPS service type | `LoadBalancer` |
| `service.control.type` | Control service type | `LoadBalancer` |
| `ingress.enabled` | Enable ingress | `false` |
| `autoscaling.enabled` | Enable HPA | `true` |
| `autoscaling.minReplicas` | Min replicas | `2` |
| `autoscaling.maxReplicas` | Max replicas | `10` |
| `metrics.enabled` | Enable metrics | `true` |

See `values.yaml` for all available options.

## Upgrading

```bash
helm upgrade tachyon ./tachyon \
  --namespace tachyon \
  --set domain=tunnel.example.com
```

## Uninstalling

```bash
helm uninstall tachyon --namespace tachyon
kubectl delete namespace tachyon
```

## Troubleshooting

### Check pod status

```bash
kubectl get pods -n tachyon
kubectl describe pod -n tachyon <pod-name>
```

### View logs

```bash
kubectl logs -f deployment/tachyon -n tachyon
```

### Test health endpoint

```bash
kubectl port-forward svc/tachyon-control 8443:8443 -n tachyon
curl http://localhost:8443/health
```
