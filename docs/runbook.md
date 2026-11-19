# Runbook

This page takes both sides of sealift from nothing to a first import, using this page alone. The connected side runs from one Compose file. The air-gapped side runs from a Helm chart that Argo CD installs from Harbor, with values kept in your own Git repository. The page ends on a checklist whose last step imports a real archive and installs its packages from Nexus.

The page has no address, hostname, certificate or credential of your site. Every value it cannot know is written `<name>` and listed once in [the drop-in values](#the-drop-in-values). Replace them all before you start.

For the chart's values and notes, read [Helm chart](helm.md). To ask the administrators for what the install needs, forward [Request to the administrators](admin-request.md).

## Who configures what

| Who | What |
| --- | --- |
| The chart | The import service, its `/data` storage, its NetworkPolicy and its Ingress |
| Your team | ingress-nginx, oauth2-proxy and the Keycloak client: [the ingress and sign-in values](#the-ingress-and-sign-in-values) are written for them to paste |
| The administrators | The Nexus, MinIO and Keycloak accounts, the namespace, the hostname and its certificate, the Harbor project |
| You | The Secret, the values repository, the Argo CD files, the checklist |

The proof of concept shares four things with Package Pusher: the users' MinIO buckets, the Nexus npm repository, the Keycloak realm and the ingress controller. It shares nothing else. It takes a hostname of its own, a Keycloak client of its own and a cookie name of its own, and it changes none of Package Pusher's settings or its repository's rules.

Package Pusher takes the first object under `packages/npm/` in a user's bucket and deletes it, even after a failed publish. Tell users not to start a Package Pusher publish on a folder that holds a sealift archive. An archive exported by v0.6.0 or later no longer passes Package Pusher's check.

## The drop-in values

Each value below is found once and used in every place the table names. The placeholders are the ones `charts/sealift/values-example.yaml` holds, and the chart refuses to render while one is left.

| Name | Provided by | Goes to | Secret |
| --- | --- | --- | --- |
| `<namespace>` | Administrators | Application `destination.namespace`, every `kubectl -n` | no |
| `<import-host>` | Administrators | `ingress.host`, the oauth2-proxy redirect URL, the Keycloak client's redirect URI and web origin | no |
| `<keycloak-realm-url>` | Administrators | `keycloak.realmUrl`, the oauth2-proxy issuer | no |
| `<keycloak-client-id>` | Administrators | `keycloak.clientId`, the oauth2-proxy client id, the token's audience | no |
| `<keycloak-client-secret>` | Administrators | oauth2-proxy `OAUTH2_PROXY_CLIENT_SECRET`, in a Secret of the team | yes |
| `<cookie-name>` | Your team | oauth2-proxy `--cookie-name`, one name of the import's own | no |
| `<cookie-secret>` | Your team | oauth2-proxy `OAUTH2_PROXY_COOKIE_SECRET`, in a Secret of the team | yes |
| `<oauth2-proxy-auth-url>` | Your team | `ingress.auth.url` | no |
| `<oauth2-proxy-signin-url>` | Your team | `ingress.auth.signin` | no |
| `<oauth2-proxy-service>`, `<oauth2-proxy-namespace>`, `<oauth2-proxy-port>` | Your team | the `/oauth2/` route and `<oauth2-proxy-auth-url>` | no |
| `<ingress-namespace>` | Administrators | `networkPolicy.ingressNamespace` | no |
| `<nexus-url>` | Administrators | `nexus.url` | no |
| `<nexus-repository>` | Administrators | `nexus.repository` | no |
| `<nexus-user>` | Administrators | `nexus.user` | no |
| Nexus password | Administrators | Secret key `nexus-password` | yes |
| `<minio-url>` | Administrators | `minio.url` | no |
| MinIO access key and secret key | Administrators | Secret keys `minio-access-key` and `minio-secret-key` | yes |
| `<secret-name>` | You | `secret.name`, the name in `kubectl create secret` | no |
| `<public-key-pem>` | The connected side | `publicKey.pem`, from sealift's Settings | no |
| `<ca-pem>` | Administrators | `ca.pem`, one file for every internal certificate authority | no |
| `<storage-class>` | Administrators | `persistence.storageClass`, empty for the cluster default | no |
| `<harbor-host>`, `<harbor-project>` | Administrators | `image.repository`, the Application's `repoURL`, the Argo CD repository Secret | no |
| Harbor robot accounts | Administrators | `docker login` and `helm registry login` for pushing, `imagePullSecrets` and the Argo CD repository Secret for pulling | yes |
| `<values-repo-url>`, `<values-path>` | You | the Application's second source | no |
| `SEALIFT_PORT`, `SEALIFT_IMAGE` | You | `deploy/connected/.env`, the connected side's port and image | no |

No value of the chart holds a credential. The three Secret keys are created by hand in [the Secret](#the-secret). The values repository is public to everyone who reads the cluster's Git, so it holds addresses, the public key and the CA certificate, which are public on the air-gapped network, and nothing else.

## Prerequisites

| Need | Version |
| --- | --- |
| Kubernetes | 1.25 or later (the chart's `kubeVersion`) |
| Helm | 3.22 or 4.3, to pull and push the chart. CI renders the chart with 3.22.1, the major Argo CD embeds, and with 4.3.1 |
| Argo CD | a release that reads OCI Helm repositories and two sources |
| ingress-nginx | the cluster's controller; its annotations below are not proven in the lab |
| oauth2-proxy | 7.15.5 ran in the lab |
| Docker | on the connected host and on the host that pushes to Harbor |
| Nexus | 3.96.5 ran in the lab |
| A network plugin that enforces NetworkPolicy | the checklist checks it |

The copy of the image that crosses is `linux/amd64` only, and the chart schedules the pod on `kubernetes.io/arch: amd64` nodes.

## The connected side

Copy `deploy/connected/compose.yaml` and `deploy/connected/.env.example` from the repository at the release tag into one folder. Rename the example to `.env`.

1. Set `SEALIFT_PORT` in `.env` when 8080 is taken, and `SEALIFT_IMAGE` to the release you carry. Start the collection role:

   <!-- illustrative -->
   ```sh
   docker compose up -d
   docker compose ps
   ```

   The service shows `healthy` after a minute. It binds `127.0.0.1` only, since sealift has no login. Reach it by an SSH tunnel or through a proxy that authenticates, as [Deployment](deployment.md#access) says.
2. Open the page and follow the setup screen, which downloads Trivy and its database. [Getting started](getting-started.md) walks through the first archive.
3. Open **Settings**, press **Download** in the signing key section and keep the file as `public-key.pem`. Read the `Public key sha256` next to it and write it down. This is the file that goes into the values and the value that the air-gapped side must show.
4. Export an archive as [Workflow](workflow.md) describes. Record the archive's sha256 on this side, before the key:

   <!-- illustrative -->
   ```sh
   shasum -a 256 packages_npm.tar.gz manifest.json manifest.json.sig
   ```
5. Carry three files, with the sha256 of the archive: `packages_npm.tar.gz`, `manifest.json` and `manifest.json.sig`. Check them against the sha256 you wrote down after the key, on the kiosk.

The volume `sealift_sealift-data` holds the private signing key. A lost volume means a new key, and the air-gapped side then refuses every archive until it holds the new public key. [Deployment](deployment.md#the-key-the-import-trusts) says how to restore a key from a backup.

## From GHCR through the key into Harbor

Everything before the key happens on the connected side. Nothing here was run end to end before the first install: it is the first run of this path, and the checks below are its test.

1. Pull the image for `linux/amd64`. Check that its architecture is `amd64`, since a pull on an arm64 Mac gives arm64 by default. Record the digest of the pull and the image id:

   <!-- illustrative -->
   ```sh
   docker pull --platform linux/amd64 ghcr.io/morgankryze/sealift:0.6.0
   docker image inspect --format '{{.Architecture}} {{.Id}} {{index .RepoDigests 0}}' ghcr.io/morgankryze/sealift:0.6.0
   ```

   The first word must be `amd64`. Write down the id (`sha256:` and 64 digits) and the digest. The digest names the manifest at GHCR. A copy pushed to Harbor can get another manifest digest, so the id is the value that you compare after the key.
2. Save the image and pull the chart:

   <!-- illustrative -->
   ```sh
   docker save ghcr.io/morgankryze/sealift:0.6.0 -o sealift-0.6.0.image.tar
   helm pull oci://ghcr.io/morgankryze/charts/sealift --version 0.6.0
   shasum -a 256 sealift-0.6.0.tgz sealift-0.6.0.image.tar
   ```

   The first `helm push` of a release creates the package `ghcr.io/morgankryze/charts/sealift`, and GHCR can make a new package private. If the pull is refused, check on GitHub that the package is public, or run `helm registry login ghcr.io` first. An Argo CD that reads GHCR directly needs the package public as well.
3. Carry the two files and the recorded values through the key. No other image crosses: oauth2-proxy and ingress-nginx are your team's.
4. On the air-gapped side, check before you push anything. Both sha256 lines must match what you recorded:

   <!-- illustrative -->
   ```sh
   shasum -a 256 sealift-0.6.0.tgz sealift-0.6.0.image.tar
   docker load -i sealift-0.6.0.image.tar
   docker image inspect --format '{{.Architecture}} {{.Id}}' ghcr.io/morgankryze/sealift:0.6.0
   ```

   The architecture must be `amd64` and the id must equal the one you recorded. Stop on any difference.
5. Push the image into `<harbor-host>/<harbor-project>` and the chart into a path apart, so that an image and a chart both named `sealift` at one version never overwrite each other:

   <!-- illustrative -->
   ```sh
   docker login <harbor-host>
   docker tag ghcr.io/morgankryze/sealift:0.6.0 <harbor-host>/<harbor-project>/sealift:0.6.0
   docker push <harbor-host>/<harbor-project>/sealift:0.6.0
   helm registry login <harbor-host>
   helm push sealift-0.6.0.tgz oci://<harbor-host>/<harbor-project>/charts
   ```

   Use the robot account that pushes. When Harbor's certificate comes from an internal authority, give `helm` its file with `--ca-file`, and install the authority for Docker as Docker's documentation says.

The tgz holds `files/published.mjs`, the script of [the rollback list](#the-rollback-list). Extract it now: `tar -xzf sealift-0.6.0.tgz sealift/files/published.mjs`.

## The Secret

The chart never creates a Secret. Create it in the namespace by hand, from three files that hold one value each and that you delete afterwards, so no value reaches your shell history or a log:

<!-- illustrative -->
```sh
kubectl create namespace <namespace>
kubectl -n <namespace> create secret generic <secret-name> \
  --from-file=nexus-password=./nexus-password \
  --from-file=minio-access-key=./minio-access-key \
  --from-file=minio-secret-key=./minio-secret-key
```

The three key names are fixed. When Harbor needs a pull credential, create it as well, from a Docker config file of the pull robot that you delete afterwards, and name it in `imagePullSecrets`:

<!-- illustrative -->
```sh
kubectl -n <namespace> create secret generic <pull-secret> \
  --type=kubernetes.io/dockerconfigjson --from-file=.dockerconfigjson=./docker-config.json
```

A plain Secret is base64. Anyone who can read Secrets in the namespace can read these three, so ask the administrators to restrict that right.

## The values in Git

Create `<values-path>/values.yaml` in `<values-repo-url>`. It starts from `charts/sealift/values-example.yaml`, which is also inside the chart:

<!-- illustrative -->
```yaml
image:
  repository: <harbor-host>/<harbor-project>/sealift
imagePullSecrets:
  - name: <pull-secret>
nexus:
  url: <nexus-url>
  repository: <nexus-repository>
  user: <nexus-user>
keycloak:
  realmUrl: <keycloak-realm-url>
  clientId: <keycloak-client-id>
minio:
  url: <minio-url>
secret:
  name: <secret-name>
publicKey:
  pem: |
    <public-key-pem>
ca:
  pem: |
    <ca-pem>
persistence:
  storageClass: <storage-class>
ingress:
  className: nginx
  host: <import-host>
  auth:
    url: <oauth2-proxy-auth-url>
    signin: <oauth2-proxy-signin-url>
networkPolicy:
  ingressNamespace: <ingress-namespace>
```

Replace every `<name>` by the value in the table, and delete a block you do not need (`imagePullSecrets` for a public image, `ca` for public certificates, `storageClass` for the default). The values file holds no credential. `keycloak.realmUrl` must equal the `iss` claim of the tokens, and `keycloak.clientId` the `aud` claim. When the realm answers to the service at an address other than the one it writes in `iss`, set `keycloak.issuer` and `keycloak.keySetUrl` as well.

When several internal authorities sign Nexus, MinIO and Keycloak, build one file with `cat nexus-ca.pem minio-ca.pem keycloak-ca.pem > ca.pem` and give that file as `ca.pem`. The service trusts it besides the system roots.

## The ingress and sign-in values

The chart's Ingress carries three annotations from the values: `auth-url`, `auth-signin` and `auth-response-headers`, the last one from `token.header`. The rest of ingress-nginx and oauth2-proxy belongs to your team. This section gives the values to paste.

What the lab proved: the oauth2-proxy settings below, which ran in `lab/compose.yaml`, and the path of the header, which ran at commit 4ca9743 with the service reading `X-Auth-Request-Access-Token` behind the lab's nginx. In that run, a request through the gateway with a forged value in both `X-Auth-Request-Access-Token` and `X-Access-Token` answered for the signed-in user, and a request straight to the service with no token answered 401 with the check `absent`.

What the lab did not prove: every ingress-nginx annotation below. They come from ingress-nginx's documentation. cairn's pages give the Ingress's shape and no sign-in. Friday's install is their first run.

### Annotations on the import's Ingress

| Annotation, under `nginx.ingress.kubernetes.io/` | Value | Where | Proven in the lab |
| --- | --- | --- | --- |
| `auth-url` | `http://<oauth2-proxy-service>.<oauth2-proxy-namespace>.svc.cluster.local:<oauth2-proxy-port>/oauth2/auth` | `ingress.auth.url` | not proven in the lab |
| `auth-signin` | `https://<import-host>/oauth2/start?rd=$scheme://$host$escaped_request_uri` | `ingress.auth.signin` | not proven in the lab |
| `auth-response-headers` | `X-Auth-Request-Access-Token` | set by the chart from `token.header` | not proven in the lab |
| `configuration-snippet` | `auth_request_set $auth_cookie $upstream_http_set_cookie;` and `add_header Set-Cookie $auth_cookie always;` | `ingress.annotations` | not proven in the lab |
| `proxy-buffer-size` | `16k` | `ingress.annotations` | not proven in the lab |

The snippet hands the refreshed session cookie to the browser on every answer. `always` keeps it on a 4xx or 5xx answer, which `add_header` drops by default. Without it, oauth2-proxy renews the session on every request. The 16k buffer holds oauth2-proxy's answer, which carries a session cookie of about 3.3 KiB next to the token headers: with the default 4k buffer, a request a minute after sign-in failed in the lab's nginx with `upstream sent too big header`. If ingress-nginx runs with snippet annotations disabled, the cookie line goes into the controller's own configuration, and your team decides how.

Put the last two in `ingress.annotations`:

<!-- illustrative -->
```yaml
ingress:
  annotations:
    nginx.ingress.kubernetes.io/proxy-buffer-size: 16k
    nginx.ingress.kubernetes.io/configuration-snippet: |
      auth_request_set $auth_cookie $upstream_http_set_cookie;
      add_header Set-Cookie $auth_cookie always;
```

The chart refuses to render an Ingress with an empty `auth-url` or `auth-signin`, and the chart's three sign-in annotations win over a same-named annotation in `ingress.annotations`.

### The route of `/oauth2/`

oauth2-proxy answers on the import's host, so the cookie belongs to that host. Your team adds an Ingress for `/oauth2` on `<import-host>`, in oauth2-proxy's namespace. Its shape, not proven in the lab:

<!-- illustrative -->
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: <oauth2-proxy-service>-import
  namespace: <oauth2-proxy-namespace>
spec:
  ingressClassName: nginx
  tls:
    - hosts: [<import-host>]
      secretName: <import-tls-secret>
  rules:
    - host: <import-host>
      http:
        paths:
          - path: /oauth2
            pathType: Prefix
            backend:
              service:
                name: <oauth2-proxy-service>
                port:
                  number: <oauth2-proxy-port>
```

### The oauth2-proxy settings

These ran in the lab, except the values that differ on a cluster (the cookie name, the secure cookie and the hostnames). Pass the two secrets by environment variable from a Secret of your team, never as an argument:

<!-- illustrative -->
```sh
--provider=keycloak-oidc
--client-id=<keycloak-client-id>
--oidc-issuer-url=<keycloak-realm-url>
--redirect-url=https://<import-host>/oauth2/callback
--whitelist-domain=<import-host>
--code-challenge-method=S256
--reverse-proxy=true
--set-xauthrequest=true
--pass-access-token=true
--cookie-refresh=1m
--cookie-name=<cookie-name>
--cookie-secure=true
--upstream=static://202
--email-domain=*
```

`OAUTH2_PROXY_CLIENT_SECRET` holds `<keycloak-client-secret>` and `OAUTH2_PROXY_COOKIE_SECRET` holds `<cookie-secret>`. In the lab, Keycloak writes `iss` as the browser's address while the service fetches keys at another, so the lab skips OIDC discovery and names each endpoint. On a cluster where the issuer address works from inside, discovery stays on.

`--pass-access-token` and `--set-xauthrequest` make the token header exist. `--cookie-refresh=1m` renews the access token before Keycloak's 5-minute lifetime ends. A session lasts as long as the refresh works.

If your team reuses an oauth2-proxy instance of another application, these settings change that application's behaviour: the access token is passed to every upstream, the `X-Auth-Request` headers are set, the session is refreshed every minute, the cookie name is shared, and the client and redirect URL belong to the import. Run an instance of the import's own.

## Argo CD

Edit the two files of `deploy/argocd/` in the Git repository of your team, replacing every `<name>`:

- `repository.yaml` registers Harbor's chart path. Its `url` has no `oci://` prefix and the file holds no credential. Apply it, then add the pull robot's `username` and `password` to the Secret in the cluster with `kubectl -n argocd edit secret sealift-charts`, never to the file.
- `application.yaml` reads the chart from Harbor at the release in `targetRevision`, reads the values from `<values-repo-url>` as `$values`, creates the namespace, and syncs by hand.

<!-- illustrative -->
```sh
kubectl apply -f deploy/argocd/repository.yaml
kubectl apply -f deploy/argocd/application.yaml
```

The chart marks the claim it creates so that `helm uninstall` and an Argo CD prune or delete keep it and its data.

## The sync

In Argo CD, open the Application `sealift`, review the diff, and sync. A render error names the value's key, since the chart fails before anything reaches the cluster. Then watch the pod:

<!-- illustrative -->
```sh
kubectl -n <namespace> get pods -w
kubectl -n <namespace> logs deploy/sealift
```

Argo CD renders the chart with `helm template` and shows no install notes. This page holds what the notes would print: the log command, the Secret, the key check and the network policy check.

## The checklist

Run the steps in order. A step is done when its expected result shows. The list ends on an archive imported `complete` and its packages installed from Nexus: a ready pod alone shows nothing about Nexus or MinIO.

| Step | Expected result | When it fails: look for | Fix |
| --- | --- | --- | --- |
| 1. The pod | `kubectl -n <namespace> get pods` shows `1/1 Running`, and the log says it listens | `ContainerCreating` with an event naming the Secret | Create the Secret of [the Secret](#the-secret) with its three keys |
| | | `CrashLoopBackOff` and exit code 2, with a log line that names a settings field, `token.header` included | Correct the value the line names. The service refuses to start on an empty header, an invalid name, or `Authorization`, `Cookie` or `Host` |
| | | `ImagePullBackOff` | Check `image.repository`, `imagePullSecrets` and the robot account |
| | | `Pending` | Check the claim's storage class and the `amd64` node selector |
| 2. TLS to the three services | The log shows no certificate error after the first request that reads MinIO, Nexus or Keycloak | `x509: certificate signed by unknown authority` | Give the authority in `ca.pem`, one bundle file for all three |
| 3. Sign in | Opening `https://<import-host>/` sends you to Keycloak, and back to the **Archives** screen with your name in the header | A redirect loop or a 500 at `/oauth2/` | Check the `/oauth2/` route and `--redirect-url` |
| 4. The token | **Archives** lists your folder without an error | 401 naming `issuer`, `audience` or `signature` | Compare `keycloak.realmUrl` with the token's `iss`, `keycloak.clientId` with `aud`, and `keycloak.keySetUrl` with the realm's keys |
| | | 401 `absent` on every call after sign-in | The ingress forwards another header than `token.header`, or oauth2-proxy does not pass the access token. Check `auth-response-headers` and `--pass-access-token` |
| 5. A minute after sign-in | Reload the screen: it still answers | `upstream sent too big header`, or a 502 | Set `proxy-buffer-size` to `16k` and the cookie snippet |
| 6. MinIO | **Archives** says `No archive in your folder` or lists archives | `MinIO is not configured` | The values hold no `minio.url`, or the settings file has no `minio` section |
| | | `MinIO has no bucket user-<name> yet: nothing to list` | Ask the administrators for the bucket `user-<name>` of the signed-in user |
| 7. The trusted key | The Settings sheet's `Public key sha256` equals the one from step 3 of [the connected side](#the-connected-side) | A different value | The key in the values is from another volume. Download it again from the volume that exports |
| 8. The network policy | Run the command under this table from a pod in another namespace. The pod starts and prints `blocked: TimeoutError` or `blocked: TypeError` | `reached 200` | The network plugin ignores the NetworkPolicy. Ask the administrators to enable enforcement before anyone relies on the policy |
| | | The pod never starts (`ErrImagePull`, `Pending`), or kubectl ends with `timed out waiting for the condition`, and no line is printed | The check proved nothing. Fix the pull (see below) and run it again |
| 9. A forged header | Through the ingress, send your session cookie and a forged `X-Auth-Request-Access-Token` and `X-Access-Token`: the answer is for you, the signed-in user | The answer is for the forged value, or a 200 without a cookie | The ingress does not replace the header on every request. Check `auth-response-headers` |
| 10. An import | In **Archives**, start the archive from [the connected side](#the-connected-side) with its sha256 in `Expected sha256 (optional)`. The import ends `Complete` | `Refused` with the signature check named | The trusted key differs from the exporting key. Redo step 7 |
| | | `Incomplete` | Retry. Never remove anything: [the worst cases](#worst-cases-on-the-shared-repository) say why |
| 11. A real install | In a project whose lockfile names the archive's packages: `pnpm install --frozen-lockfile --registry <nexus-url>/repository/<nexus-repository>/` installs them | A `404` for a package | The import is not `Complete`, or the repository is not the one in the settings |
| 12. Memory | After step 10, `kubectl -n <namespace> top pod` shows the peak. Write it down | An `OOMKilled` pod | Raise `resources.limits.memory`. The attempt ended `interrupted`, and a retry continues it |

### Step 8, the network policy check

Step 8 needs a network plugin that enforces NetworkPolicy. Without it, any pod of the cluster can reach the service, which still checks every token. The check runs the sealift image that Harbor already serves, so no other image crosses. `<other-namespace>` is any namespace that is neither `<namespace>` nor `<ingress-namespace>`. The service is named `sealift` after the Application:

<!-- illustrative -->
```sh
kubectl -n <other-namespace> run reach-check --rm -i --restart=Never \
  --image=<harbor-host>/<harbor-project>/sealift:0.6.0 \
  --command -- node -e 'fetch("http://sealift.<namespace>.svc:8080/healthz",{signal:AbortSignal.timeout(5000)}).then(r=>console.log("reached",r.status),e=>console.log("blocked:",e.name))'
```

The expected result is one printed line, `blocked: TimeoutError` (the packet was dropped) or `blocked: TypeError` (the connection was refused). A `reached 200` line means the policy is not enforced.

A pod that never starts proves nothing, and kubectl then ends with `timed out waiting for the condition`, which looks like a timeout. Open `kubectl -n <other-namespace> get pod reach-check` in a second terminal. If the pod is in `ErrImagePull` or `ImagePullBackOff`, the other namespace lacks the pull secret: create `<pull-secret>` there as [the Secret](#the-secret) shows, and add `--overrides='{"spec":{"imagePullSecrets":[{"name":"<pull-secret>"}]}}'`. A namespace that enforces the `restricted` standard refuses the pod at once, with a message that names the rule: take a namespace that does not.

## Upgrades

1. Carry the new image and chart through [Harbor](#from-ghcr-through-the-key-into-harbor).
2. Bump `targetRevision` in `application.yaml` to the new release, and `image.tag` if you pin it.
3. Open **Imports** and wait until none is queued or running.
4. Sync. An import that is running at the sync ends `interrupted`, and a retry continues it.

The connected side changes `SEALIFT_IMAGE` in `.env`, then `docker compose pull && docker compose up -d`. Sessions, archives, settings and the key carry over.

## Backup and restore

Take both while no job runs.

The import's records, under `/data/imports`:

<!-- illustrative -->
```sh
kubectl -n <namespace> exec deploy/sealift -- tar czf - -C /data imports > imports-backup.tgz
```

To restore, extract the file into the same path of a new pod (`kubectl exec -i deploy/sealift -- tar xzf - -C /data < imports-backup.tgz`) before any import starts, and run `chown` only if the files do not belong to uid 10000. The claim itself survives `helm uninstall` and an Argo CD prune.

The collection's volume holds the private key. Stop the container, archive the volume, and start again:

<!-- illustrative -->
```sh
docker compose stop sealift
docker run --rm -v sealift_sealift-data:/data:ro -v "$PWD":/backup alpine \
  tar czf /backup/sealift-data.tar.gz --exclude=./cache --exclude=./trivy-cache -C /data .
docker compose start sealift
```

Keep that archive as you keep the key.

## Logs

| Side | Command |
| --- | --- |
| Import service | `kubectl -n <namespace> logs deploy/sealift` |
| Collection | `docker compose logs -f sealift` |

## Worst cases on the shared repository

The import publishes into the npm hosted repository that Package Pusher writes to. That repository is production: a package an import publishes is installable at once by every project that reads it. Each worst case has its guard.

| Worst case | Guard |
| --- | --- |
| A wrong archive reaches Nexus | The import writes nothing until the signature verifies with the trusted key, the sha256 you give matches, the archive's sha256 and size match the manifest, and each tarball matches its manifest entry. Fill `Expected sha256 (optional)` on every import into this repository, with the value recorded before the key |
| A version Nexus holds is replaced | The import reads each version before its upload and fails one held with other bytes (kind `conflict`), and reads it back after and fails one Nexus serves with other bytes (kind `nexus`). The repository allows redeploy and the request asks no change, since Package Pusher republishes there |
| A race with Package Pusher | Never start a Package Pusher publish into the repository while an import is queued or running. A version uploaded by both tools between the import's check and its upload leaves the last writer's bytes. **Imports** and an import's panel show `Queued` and `Running`: [Importing](importing.md#imports) |
| A partial publish | An attempt that ends `Incomplete` keeps what it published, the archive and its manifest in MinIO, and its records. A project whose lockfile names a missing package cannot install until a retry ends `Complete`. The next step is the retry, which uploads only what Nexus lacks, never a removal |
| A newer `latest` | See below |
| A rollback | See [the rollback list](#the-rollback-list) |

### The `latest` tag

The import writes no dist-tag. It uploads tarballs through Nexus's component upload and nothing else. A lab run on 2026-11-19 on Nexus 3.96.5 showed what Nexus does with `latest` on such an upload: uploading 2.0.0, then 1.0.0, then 1.5.0 kept `latest` at 2.0.0; a prerelease 3.0.0-beta.1 kept it at 2.0.0; a newer stable 2.1.0 moved it to 2.1.0. So an upload never moves `latest` backward or to a prerelease, and moves it forward when it carries a newer stable version than the repository holds. A bare `npm install <name>` then gets that version. An install from a lockfile or a range does not change. The run did not cover `npm publish`, which Package Pusher uses.

Where the target Nexus is another version, this is not proven there. Before the first import, run the check on a hosted npm repository other than the shared one. Upload a probe package at `2.0.0`, `1.0.0`, `1.5.0`, `3.0.0-beta.1` and `2.1.0` in that order, and read the tag after each upload:

<!-- illustrative -->
```sh
npm pack ./probe
curl -u <nexus-user> -F "npm.asset=@probe-2.0.0.tgz" "<nexus-url>/service/rest/v1/components?repository=<test-repository>"
curl -s <nexus-url>/repository/<test-repository>/probe | node -e 'process.stdin.on("data",d=>console.log(JSON.parse(d)["dist-tags"]))'
```

`latest` must stay at `2.0.0` through the second, third and fourth upload and move to `2.1.0` on the last. Remove the probe afterwards.

### The rollback list

sealift holds no delete right in Nexus, and this kit adds no route to delete. A rollback is an administrator's act, from a list that the import's records give. The list holds, for one import, every package that any of its attempts published, as `name@version`. It never holds a package that was only `present`, which Nexus held before the import and which may be Package Pusher's. It lists apart the packages that may have landed: a package that failed with the kind `interrupted` or `nexus`, a package left pending, and a failure with no kind.

The records sit under `/data/imports/<user>/<id>/import.json`. The script reads one record and writes nothing:

<!-- illustrative -->
```sh
kubectl -n <namespace> exec deploy/sealift -- ls /data/imports/<user>
kubectl -n <namespace> exec -i deploy/sealift -- node - /data/imports/<user>/<id>/import.json < sealift/files/published.mjs
```

The output has two parts, `Published by this import:` and `Possibly published, check each in Nexus first:`. An import that ended `Complete` has the first part only.

Steps for the administrator:

1. For each package under `Published by this import:`, decide whether it must go. Deleting a version breaks any project that installed it since.
2. For each package under the second heading, check in Nexus before you delete anything. A `nexus` failure that never reached an upload, such as a failed repository check or a failed read before the upload, can name a version that Package Pusher published. Open the import in the screens and read the package's reason: a reason that starts with `repository check failed:` was never uploaded, so leave it. Otherwise open the component in Nexus under **Browse**, and read its asset: the uploader must be the sealift publisher user and the upload time must fall within the import's attempt. Delete the component only when both hold.
3. In Nexus, open **Browse**, select the repository, find the component, select **Delete component**, and confirm. The same is available through the REST API as `DELETE /service/rest/v1/components/<component-id>` for a user with the delete privilege.
4. Record what you deleted.

What a deletion does to `latest` and to the package's metadata is not proven in the lab. A package found bad after the import goes through the same list.
