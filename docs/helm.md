# Helm chart

This page covers the chart that installs `sealift import-server`, the import service of the air-gapped side, on Kubernetes: its values, its install notes, how it is published and how Argo CD reads it. The collection role has no chart: it runs from the Compose file of [the runbook](runbook.md#the-connected-side). To install step by step, follow the runbook.

The chart runs one container, sealift's, and ships no gateway: no nginx, no oauth2-proxy, no cookie secret and no client secret. Users sign in through the cluster's ingress-nginx and an oauth2-proxy that your team runs.

## What the chart installs

| Object | Purpose |
| --- | --- |
| Deployment | One pod, replaced by stopping the old pod before the new one starts (`Recreate`), so two queues never run on the same `/data`. No value raises the count |
| ConfigMap | The service's settings file, built from the values, and the public key and CA files when the values hold them |
| PersistentVolumeClaim | `/data`, unless persistence is off or a claim is named. Kept by Helm and by Argo CD |
| Service | `ClusterIP` on the service port |
| Ingress | One host and one path, with ingress-nginx's sign-in annotations |
| NetworkPolicy | Admits the pod only from the ingress controller's namespace |

The pod runs as a non-root user, with a read-only root filesystem, every capability dropped, no privilege escalation and the `RuntimeDefault` seccomp profile. A namespace that enforces the Kubernetes `restricted` standard admits it. The chart needs Kubernetes 1.25 or later.

The chart's version and `appVersion` both equal the release: version 0.8.0 runs the image `ghcr.io/morgankryze/sealift:0.8.0`.

## Values

An empty value marked required is a drop-in. The chart refuses to render until it is filled and names the key. A string value that still holds a placeholder such as `<nexus-url>` is refused the same way, wherever it sits: `image.repository`, `imagePullSecrets`, `ca.pem`, an annotation. No value turns certificate checks off, and no value holds a credential.

| Key | Default | Meaning |
| --- | --- | --- |
| `image.repository` | `ghcr.io/morgankryze/sealift` | The image. Set it to the copy in Harbor |
| `image.tag` | empty | Empty means the chart's `appVersion` |
| `image.digest` | empty | When set, the pod pulls this digest |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | Secrets that let the pod pull from Harbor |
| `nexus.url` | required | The Nexus address. Use `https://`: the chart accepts `http://` here, and the install notes warn |
| `nexus.repository` | required | The npm hosted repository the import publishes into |
| `nexus.user` | required | The import's Nexus user |
| `nexus.pipRepository` | empty | Optional. The pypi hosted repository the import publishes pip archives into. Empty renders no pip section, and the import refuses pip archives. [The request](admin-request.md#nexus-for-python) gives the rights it needs |
| `nexus.pipUser` | empty | Optional. The Nexus user for the pypi repository. Empty means `nexus.user` and its password. When set, the Secret must hold `nexus-pip-password`, and the chart refuses to render without `nexus.pipRepository` |
| `keycloak.realmUrl` | required | The realm's address. The chart refuses `http://` and names the key |
| `keycloak.clientId` | required | The client of the import's oauth2-proxy, and the token's audience |
| `keycloak.issuer` | empty | Empty means `realmUrl` |
| `keycloak.audience` | empty | Empty means `clientId` |
| `keycloak.keySetUrl` | empty | Empty means `<realmUrl>/protocol/openid-connect/certs`. The chart refuses `http://` and names the key |
| `token.header` | `X-Auth-Request-Access-Token` | The one request header the service reads the token from. The chart writes the same value into the Ingress's `auth-response-headers` |
| `minio.url` | required | The MinIO address. Use `https://`: the chart accepts `http://` here, and the install notes warn |
| `minio.region` | `us-east-1` | |
| `secret.name` | required | A Secret you create, with the keys `nexus-password`, `minio-access-key` and `minio-secret-key`, plus `nexus-pip-password` when `nexus.pipUser` is set |
| `publicKey.pem` | required unless a ConfigMap is named | The collection's public key as one PEM block |
| `publicKey.existingConfigMap` | empty | A ConfigMap that holds the key under `public-key.pem` |
| `ca.pem` | empty | One PEM file the service trusts besides the system roots |
| `ca.existingConfigMap` | empty | A ConfigMap that holds it under `ca.pem` |
| `persistence.enabled` | `true` | Off keeps `/data` in an `emptyDir` |
| `persistence.existingClaim` | empty | A claim you created |
| `persistence.storageClass` | empty | Empty means the cluster default |
| `persistence.size` | `20Gi` | An attempt stages up to 10 GiB of unpacked tarballs. Not measured on real archives |
| `persistence.accessMode` | `ReadWriteOnce` | |
| `service.type`, `service.port` | `ClusterIP`, `8080` | |
| `ingress.enabled` | `true` | |
| `ingress.className` | empty | |
| `ingress.host` | required when enabled | The one host the service answers on, served at `/` |
| `ingress.path`, `ingress.pathType` | `/`, `Prefix` | |
| `ingress.annotations` | `{}` | Extra annotations. The three sign-in annotations win over a same-named one |
| `ingress.tls.enabled` | `true` | |
| `ingress.tls.secretName` | empty | Empty means `<fullname>-tls` |
| `ingress.auth.url` | required when enabled | The oauth2-proxy address ingress-nginx asks |
| `ingress.auth.signin` | required when enabled | Where ingress-nginx sends a user who is not signed in |
| `networkPolicy.enabled` | `true` | |
| `networkPolicy.ingressNamespace` | `ingress-nginx` | The ingress controller's namespace |
| `networkPolicy.ingressPodLabels` | `{}` | Narrows the admitted peers to the controller's pods |
| `resources` | 100m CPU and 256Mi requested, 1Gi memory limit | No CPU limit. Not measured on a real archive |
| `podSecurityContext`, `securityContext` | non-root, user 10000, group 2000 | Needed for the `restricted` standard |
| `nodeSelector` | `kubernetes.io/arch: amd64` | The copy kept in Harbor holds `linux/amd64` only |
| `tolerations`, `affinity`, `podAnnotations` | empty | |

`charts/sealift/values-example.yaml` lists the drop-ins with placeholders. As shipped it fails to render and names its first unfilled key. It renders once every placeholder is replaced.

## Storage

Persistence is on by default. The chart creates a claim with `helm.sh/resource-policy: keep` and the Argo CD sync options `Prune=false,Delete=false`, so `helm uninstall`, and a prune or delete by Argo CD, leave the claim and its records in place. A claim left behind after a planned removal is deleted by hand, after a backup of its records: [the runbook](runbook.md#backup-and-restore) shows how, and how to restore. Take one before each upgrade as well. The service writes to it as group 2000.

With `persistence.enabled: false`, `/data` is an `emptyDir`. Import records, and an import that is running, are lost when the pod is replaced. The install notes say so.

## The ingress and the network policy

The Ingress adds `auth-url` and `auth-signin` from `ingress.auth` and `auth-response-headers` from `token.header`, so the header the ingress sets and the header the service reads come from one value. An empty `auth-url` or `auth-signin` fails the render, so the chart never renders an Ingress that skips sign-in. These annotations are not proven in the lab. [The runbook](runbook.md#the-ingress-and-sign-in-values) gives the values and says what the lab did show.

With the ingress off, the install notes print the annotations that an Ingress written by hand needs. Another controller than ingress-nginx needs its own Ingress and is not proven.

The NetworkPolicy admits traffic from the ingress controller's namespace only, narrowed by `ingressPodLabels` when set, and only on the service's port. Outgoing traffic stays open, since the service reaches Keycloak, MinIO, Nexus and DNS at addresses the chart cannot know. It takes effect only on a network plugin that enforces NetworkPolicy. With the policy off, any pod can reach the service, which still checks every token.

## The install notes

`helm install` prints notes. An Argo CD sync does not: it renders the chart with `helm template`, and the runbook holds the same commands for that case. The notes hold:

- the address, or the annotations for a hand-written Ingress;
- the command for the service's logs;
- the Secret to create and its keys, `nexus-pip-password` included when `nexus.pipUser` is set;
- the public key's sha256, to compare with the one on the collection's Instance page;
- a warning when persistence is off;
- the command that checks the network policy, which runs the release's own image in another namespace and prints one line, or a warning when the policy is off.

## Rollback list

`files/published.mjs` sits in the chart. It reads one import record and lists what the import published: [the rollback list](runbook.md#the-rollback-list).

## Argo CD

`deploy/argocd/` holds two files, with no credential in either:

- `repository.yaml` registers Harbor's OCI chart path. Its `url` has no `oci://` prefix and carries `enableOCI`.
- `application.yaml` reads the chart from Harbor at `targetRevision`, equal to the release, and reads its values from your Git repository as `$values`. It creates the namespace and has no automated sync: a person syncs each change.

Both files have placeholders for Harbor, the values repository and the namespace. [The runbook](runbook.md#argo-cd) shows how to fill and apply them.

## Release

A pushed tag `vX.Y.Z` builds the image and, once the image is published, packages the chart with version and `appVersion` `X.Y.Z` and pushes it to `oci://ghcr.io/morgankryze/charts/sealift`. A failed push fails the job and names the cause. To recover, rerun the job, or run `helm package charts/sealift --version X.Y.Z --app-version X.Y.Z` from the tag and carry the tgz. GHCR can make the package private on its first push: check that it is public before an anonymous `helm pull` or Argo CD reads it.

## Checks

`just chart` runs `helm lint --strict` and the render tests of `charts/`. The tests render the default shape and each branch: ingress with TLS, ingress off, network policy off, persistence off, `existingClaim`, a CA, pull secrets, a digest, another token header, and a pip repository with and without its own user. They check that each refusal fails the render and names its key, and that the settings file the chart renders loads through the import's own settings loader. CI runs them on every pull request with Helm 3.22.1, and the tests skip on a machine without Helm. No cluster ran the chart before the first install, and the runbook's checklist is its test.
