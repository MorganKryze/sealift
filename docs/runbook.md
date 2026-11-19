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

Each value below is found once and used in every place the table names. The chart refuses to render while a `<name>` is left in any string value, and the error names the key. `charts/sealift/values-example.yaml` holds the ones that have no default. A name that only appears in a command, such as `<other-namespace>`, is not checked: read your commands before you run them.

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
| `<other-namespace>` | You | the network policy check of the checklist, any namespace besides `<namespace>` and `<ingress-namespace>` | no |
| `<nexus-url>` | Administrators | `nexus.url` | no |
| `<nexus-repository>` | Administrators | `nexus.repository` | no |
| `<nexus-user>` | Administrators | `nexus.user` | no |
| Nexus password | Administrators | Secret key `nexus-password` | yes |
| `<minio-url>` | Administrators | `minio.url` | no |
| MinIO access key and secret key | Administrators | Secret keys `minio-access-key` and `minio-secret-key` | yes |
| `<secret-name>` | You | `secret.name`, the name in `kubectl create secret` | no |
| `<pull-secret>` | You | `imagePullSecrets`, the name in `kubectl create secret` for a Harbor pull credential | no |
| `<import-tls-secret>` | Administrators | `ingress.tls.secretName`, the name in `kubectl create secret tls`, the `/oauth2` Ingress's `secretName` | no |
| `<test-repository>` | Administrators | the probe's hosted npm repository in [the `latest` tag](#the-latest-tag) check, a repository other than the shared one, in no group | no |
| `<probe-user>` | Administrators | the account that uploads the probe, never the import's user | no |
| Probe password | Administrators | the prompt of `curl` in the same check | yes |
| `<public-key-pem>` | The connected side | `publicKey.pem`, from sealift's Settings | no |
| `<ca-pem>` | Administrators | `ca.pem`, one file for every internal certificate authority | no |
| `<storage-class>` | Administrators | `persistence.storageClass`, empty for the cluster default | no |
| `<harbor-host>`, `<harbor-project>` | Administrators | `image.repository`, the Application's `repoURL`, the Argo CD repository Secret | no |
| Harbor robot accounts | Administrators | `docker login` and `helm registry login` for pushing, `imagePullSecrets` and the Argo CD repository Secret for pulling | yes |
| `<values-repo-url>`, `<values-path>` | You | the Application's second source | no |
| `SEALIFT_PORT`, `SEALIFT_IMAGE` | You | `deploy/connected/.env`, the connected side's port and image | no |

No value of the chart holds a credential. The three Secret keys are created by hand in [the Secret](#the-secret). The values repository is public to everyone who reads the cluster's Git, so it holds addresses, the public key and the CA certificate, which are public on the air-gapped network, and nothing else.

Whoever can write to that repository can change what the service trusts and where it sends its credentials. Restrict writes to a few people, and let changes reach `main` only through a review. These keys need a second look at every sync, since each one moves trust or reach: `publicKey`, `ca`, `keycloak.*`, `token.header`, `nexus.url`, `minio.url`, `image.*`, `ingress.annotations` and `networkPolicy.*`. After any change to `publicKey`, redo step 7 of [the checklist](#the-checklist) and compare the fingerprint again.

The Keycloak, Nexus and MinIO addresses are `https://` URLs. The chart refuses `http://` for `keycloak.realmUrl` and `keycloak.keySetUrl` and names the key. It accepts `http://` for `nexus.url` and `minio.url`, so only you keep them on https: over `http://` the Nexus password and every archive cross the network in the clear.

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

1. Set `SEALIFT_PORT` in `.env` when 8080 is taken, and `SEALIFT_IMAGE` to the release you carry. The Compose file keeps a volume named `sealift-data` that exists already, such as the one of a `docker run` install, and does not create one. Create it, then start the collection role:

   <!-- illustrative -->
   ```sh
   docker volume create sealift-data
   docker compose up -d
   docker compose ps
   ```

   `docker volume create` prints `sealift-data`, also when the volume exists, and changes nothing then. Without it, `docker compose up` stops with `external volume "sealift-data" not found`. The service shows `healthy` after a minute. It binds `127.0.0.1` only, since sealift has no login. Reach it by an SSH tunnel or through a proxy that authenticates, as [Deployment](deployment.md#access) says.
2. Open the page and follow the setup screen, which downloads Trivy and its database. [Getting started](getting-started.md) walks through the first archive.
3. Open **Settings**, press **Download** in the signing key section and keep the file as `public-key.pem`. Read the `Public key sha256` next to it and write it down. This is the file that goes into the values and the value that the air-gapped side must show. Send the fingerprint by [another channel](#values-that-cross-by-another-channel).
4. Export an archive as [Workflow](workflow.md) describes. Record the archive's sha256 on this side, before the key:

   <!-- illustrative -->
   ```sh
   shasum -a 256 packages_npm.tar.gz manifest.json manifest.json.sig
   ```
5. Carry three files: `packages_npm.tar.gz`, `manifest.json` and `manifest.json.sig`. Send the archive's sha256 by [another channel](#values-that-cross-by-another-channel), and check the three files against it on the kiosk.

The volume `sealift-data` holds the private signing key. A lost volume means a new key, and the air-gapped side then refuses every archive until it holds the new public key. [Deployment](deployment.md#the-key-the-import-trusts) says how to restore a key from a backup.

## Values that cross by another channel

Five values prove that what arrives is what left: the public key and its `Public key sha256`, the archive's sha256, the image id, and the sha256 of the chart tgz and of the image tar. Send them by a channel that is neither the kiosk nor the USB key: a ticket, a call, a printed sheet. A copy that crosses on the key proves nothing, since whoever swaps a file swaps the value beside it. Every comparison below uses the copy you received by that channel: the key's fingerprint at step 7 of [the checklist](#the-checklist), the archive's sha256 in `Expected sha256 (optional)`, and the image id and the two sha256 lines at the Harbor step.

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
3. Carry the two files through the key and send the recorded values by [another channel](#values-that-cross-by-another-channel). No other image crosses: oauth2-proxy and ingress-nginx are your team's.
4. On the air-gapped side, check before you push anything. Both sha256 lines must match the values you received by the other channel:

   <!-- illustrative -->
   ```sh
   shasum -a 256 sealift-0.6.0.tgz sealift-0.6.0.image.tar
   docker load -i sealift-0.6.0.image.tar
   docker image inspect --format '{{.Architecture}} {{.Id}}' ghcr.io/morgankryze/sealift:0.6.0
   ```

   The architecture must be `amd64` and the id must equal the one you received by the other channel. Stop on any difference.
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

The chart never creates a Secret. Create it in the namespace by hand, from three files that hold one value each and that you delete afterwards, so no value reaches your shell history or a log. Run these lines in bash (`read -rs -p` behaves differently in zsh and would write an empty file there); `read -rs` prompts for a value without echoing it. Write each file readable by you alone:

<!-- illustrative -->
```sh
umask 077
read -rs -p 'Nexus password: ' v; printf '%s' "$v" > nexus-password; echo
read -rs -p 'MinIO access key: ' v; printf '%s' "$v" > minio-access-key; echo
read -rs -p 'MinIO secret key: ' v; printf '%s' "$v" > minio-secret-key; echo
unset v
kubectl create namespace <namespace>
kubectl -n <namespace> create secret generic <secret-name> \
  --from-file=nexus-password=./nexus-password \
  --from-file=minio-access-key=./minio-access-key \
  --from-file=minio-secret-key=./minio-secret-key
rm nexus-password minio-access-key minio-secret-key
```

The three key names are fixed. When Harbor needs a pull credential, create it as well, from a Docker config file of the pull robot that you delete afterwards, and name it in `imagePullSecrets`:

<!-- illustrative -->
```sh
kubectl -n <namespace> create secret generic <pull-secret> \
  --type=kubernetes.io/dockerconfigjson --from-file=.dockerconfigjson=./docker-config.json
```

A plain Secret is base64. Anyone who can read Secrets in the namespace can read these three, so ask the administrators to restrict that right. Three more Secrets need the same restriction: the pull Secret, the TLS Secret `<import-tls-secret>` in `<namespace>`, and its copy in `<oauth2-proxy-namespace>`, which holds the same private key a second time. oauth2-proxy's own Secret, with the client secret and the cookie secret, belongs to your team.

## The certificate

The import's Ingress serves `<import-host>` over TLS from a Secret of type `kubernetes.io/tls` in `<namespace>`. The chart never creates it. Ask the administrators for the certificate and its key (the [request](admin-request.md) asks for them), then create the Secret from two files that you delete afterwards:

<!-- illustrative -->
```sh
kubectl -n <namespace> create secret tls <import-tls-secret> \
  --cert=./import-host.crt --key=./import-host.key
```

The values name it in `ingress.tls.secretName`. Without that key, the Ingress asks for a Secret named `sealift-tls`. The certificate file holds the full chain, the host's certificate first.

The `/oauth2` Ingress of [the route of `/oauth2/`](#the-route-of-oauth2) names `<import-tls-secret>` as its `secretName`. An Ingress reads a Secret from its own namespace only, so create the same Secret in `<oauth2-proxy-namespace>`, with the same command and `-n <oauth2-proxy-namespace>`.

A controller that serves a default certificate for `<import-host>` is the alternative. Set `ingress.tls.enabled: false`, so that the Ingress has no `tls` block, remove `ingress.tls.secretName` from the values, drop the `tls` block of the `/oauth2` Ingress, and add `nginx.ingress.kubernetes.io/force-ssl-redirect: "true"` to `ingress.annotations`, since ingress-nginx redirects to HTTPS on its own only for an Ingress with a `tls` block. The install notes then print an `http://` address: open it as `https://`.

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
  tls:
    secretName: <import-tls-secret>
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

What the lab did not prove: every ingress-nginx annotation below. They come from ingress-nginx's documentation. The first install on the cluster is their first run, and the checklist is their test.

### Annotations on the import's Ingress

| Annotation, under `nginx.ingress.kubernetes.io/` | Value | Where | Proven in the lab |
| --- | --- | --- | --- |
| `auth-url` | `http://<oauth2-proxy-service>.<oauth2-proxy-namespace>.svc.cluster.local:<oauth2-proxy-port>/oauth2/auth` | `ingress.auth.url` | not proven in the lab |
| `auth-signin` | `https://<import-host>/oauth2/start?rd=$scheme://$host$escaped_request_uri` | `ingress.auth.signin` | not proven in the lab |
| `auth-response-headers` | `X-Auth-Request-Access-Token` | set by the chart from `token.header` | not proven in the lab |
| `auth-always-set-cookie` | `"true"` | `ingress.annotations` | not proven in the lab |
| `proxy-buffer-size` | `16k` | `ingress.annotations` | not proven in the lab |

`auth-always-set-cookie` hands the refreshed session cookie to the browser on every answer, including a 4xx or 5xx one, which ingress-nginx drops by default. Without it, oauth2-proxy renews the session on every request. The 16k buffer holds oauth2-proxy's answer, which carries a session cookie of about 3.3 KiB next to the token headers: with the default 4k buffer, a request a minute after sign-in failed in the lab's nginx with `upstream sent too big header`.

Put both in `ingress.annotations`:

<!-- illustrative -->
```yaml
ingress:
  annotations:
    nginx.ingress.kubernetes.io/proxy-buffer-size: 16k
    nginx.ingress.kubernetes.io/auth-always-set-cookie: "true"
```

A fallback exists for a controller that lacks `auth-always-set-cookie`, and only where your team allows snippet annotations. ingress-nginx refuses them by default since controller 1.9, and its admission webhook then rejects the whole Ingress. Replace the second line with this one, which does by hand what `auth-always-set-cookie` does:

<!-- illustrative -->
```yaml
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

The Secret `<import-tls-secret>` must exist in `<oauth2-proxy-namespace>`: [the certificate](#the-certificate) shows the command. It holds the TLS private key a second time, so restrict who reads Secrets there too.

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

In Argo CD, open the Application `sealift`, review the diff, and sync. Read the diff of `publicKey`, `ca`, `keycloak.*`, `token.header`, `nexus.url` and `minio.url` line by line, as [the drop-in values](#the-drop-in-values) say. A render error names the value's key, since the chart fails before anything reaches the cluster. Then watch the pod:

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
| | | The sync fails with `admission webhook "validate.nginx.ingress.kubernetes.io" denied the request` and a message such as `annotation group ConfigurationSnippet contains risky annotation` | The controller refuses snippet annotations. Remove `configuration-snippet` from `ingress.annotations` and use `auth-always-set-cookie` as [the annotations](#annotations-on-the-imports-ingress) say. The pod can be `Running` while the Ingress does not exist, so check `kubectl -n <namespace> get ingress` |
| 2. TLS to the three services | The log shows no certificate error after the first request that reads MinIO, Nexus or Keycloak | `x509: certificate signed by unknown authority` | Give the authority in `ca.pem`, one bundle file for all three |
| 3. Sign in | Opening `https://<import-host>/` sends you to Keycloak, and back to the **Archives** screen with your name in the header | A redirect loop or a 500 at `/oauth2/` | Check the `/oauth2/` route and `--redirect-url` |
| 4. The token | **Archives** lists your folder without an error | 401 naming `issuer`, `audience` or `signature` | Compare `keycloak.realmUrl` with the token's `iss`, `keycloak.clientId` with `aud`, and `keycloak.keySetUrl` with the realm's keys |
| | | 401 `absent` on every call after sign-in | The ingress forwards another header than `token.header`, or oauth2-proxy does not pass the access token. Check `auth-response-headers` and `--pass-access-token` |
| 5. A minute after sign-in | Reload the screen: it still answers | `upstream sent too big header`, or a 502 | Set `proxy-buffer-size` to `16k` and `auth-always-set-cookie` to `"true"` |
| 6. MinIO | **Archives** says `No archive in your folder` or lists archives | `MinIO is not configured` | The values hold no `minio.url`, or the settings file has no `minio` section |
| | | `MinIO has no bucket user-<name> yet: nothing to list` | Ask the administrators for the bucket `user-<name>` of the signed-in user |
| 7. The trusted key | The Settings sheet's `Public key sha256` equals the fingerprint that step 3 of [the connected side](#the-connected-side) wrote down, as you received it by [another channel](#values-that-cross-by-another-channel) | A different value | The key in the values is from another volume. Download it again from the volume that exports |
| 8. The network policy | First run the command under this table with `-n <ingress-namespace>`: it must print `reached 200`, which proves the address and the port. Then run it from a pod in another namespace: the pod starts and prints a line that begins `blocked: TimeoutError`. No other line passes, and a timeout without the first run proves nothing (a wrong port also times out) | `reached 200` | The network plugin ignores the NetworkPolicy. Ask the administrators to enable enforcement before anyone relies on the policy |
| | | `blocked: TypeError ENOTFOUND` | The address is wrong: the name `sealift.<namespace>.svc` did not resolve. The check proved nothing. Correct `<namespace>` and run it again |
| | | `blocked: TypeError ECONNREFUSED` | A host answered with a refusal, so no packet was dropped. Run `kubectl -n <namespace> get endpoints sealift`: with no address, the service has no ready pod and the check proved nothing. With an address, the policy does not drop the traffic: ask the administrators whether the plugin enforces NetworkPolicy and how it treats a denied connection |
| | | The pod never starts (`ErrImagePull`, `Pending`), or kubectl ends with `timed out waiting for the condition`, and no line is printed | The check proved nothing. Fix the pull (see below) and run it again |
| 9. A forged header | Run the commands under this table. The first answers 200 with your user name. The second, with forged headers added, answers 200 with the same name | Any 401, a name other than yours, or a 200 without the cookie | The ingress does not replace the header on every request. Check `auth-response-headers` |
| 10. An import | In **Archives**, start the archive from [the connected side](#the-connected-side) with its sha256 in `Expected sha256 (optional)`. The import ends `Complete` | `Refused` with the signature check named | The trusted key differs from the exporting key. Redo step 7 |
| | | `Incomplete` | Retry. Never remove anything: [the worst cases](#worst-cases-on-the-shared-repository) say why |
| 11. A real install | In a project whose lockfile names the archive's packages: `pnpm install --frozen-lockfile --registry <nexus-url>/repository/<nexus-repository>/` installs them | A `404` for a package | Nexus does not hold it. Look for an import that is not `Complete`, a version that an administrator removed since (see [the rollback list](#the-rollback-list)), a lockfile that names a package the archive did not carry, or a registry address other than `<nexus-url>/repository/<nexus-repository>/` |
| 12. Memory | After step 10, `kubectl -n <namespace> top pod` shows the peak. Write it down | An `OOMKilled` pod | Raise `resources.limits.memory`. The attempt ended `interrupted`, and a retry continues it |

### Step 8, the network policy check

Step 8 needs a network plugin that enforces NetworkPolicy. Without it, any pod of the cluster can reach the service, which still checks every token. The check runs the sealift image that Harbor already serves, so no other image crosses. `<other-namespace>` is any namespace that is neither `<namespace>` nor `<ingress-namespace>`. The service is named `sealift` after the Application:

<!-- illustrative -->
```sh
kubectl -n <other-namespace> run reach-check --rm -i --restart=Never \
  --image=<harbor-host>/<harbor-project>/sealift:0.6.0 \
  --command -- node -e 'fetch("http://sealift.<namespace>.svc:8080/healthz",{signal:AbortSignal.timeout(5000)}).then(r=>console.log("reached",r.status),e=>console.log(["blocked:",e.name,e.cause&&e.cause.code].filter(Boolean).join(" ")))'
```

The expected result is one printed line that begins `blocked: TimeoutError`: the packet was dropped, so the policy is enforced. A `reached 200` line means the policy is not enforced. Any `blocked: TypeError` line, with `ENOTFOUND` or `ECONNREFUSED` after it, is not a pass: the table says what each means.

A pod that never starts proves nothing, and kubectl then ends with `timed out waiting for the condition`, which looks like a timeout. Open `kubectl -n <other-namespace> get pod reach-check` in a second terminal. If the pod is in `ErrImagePull` or `ImagePullBackOff`, the other namespace lacks the pull secret: create `<pull-secret>` there as [the Secret](#the-secret) shows, and add `--overrides='{"spec":{"imagePullSecrets":[{"name":"<pull-secret>"}]}}'`. A namespace that enforces the `restricted` standard refuses the pod at once, with a message that names the rule: take a namespace that does not.

That copy of the pull credential must not stay in a namespace that is not yours. Delete it when the check is done:

<!-- illustrative -->
```sh
kubectl -n <other-namespace> delete secret <pull-secret>
```

The command prints `secret "<pull-secret>" deleted`. An error `not found` means that no copy was left.

### Step 9, the forged header check

Sign in in a browser, open the developer tools and copy the session cookie of `<import-host>`: its name starts with `<cookie-name>`, and a session that does not fit one cookie is split into `<cookie-name>_0`, `<cookie-name>_1` and so on. Send every part. Run the baseline first, then the forged request:

<!-- illustrative -->
```sh
curl --cacert ca.pem -s -w '\n%{http_code}\n' -H 'Cookie: <cookie-name>=<session-cookie>' https://<import-host>/api/me
curl --cacert ca.pem -s -w '\n%{http_code}\n' -H 'Cookie: <cookie-name>=<session-cookie>' \
  -H 'X-Auth-Request-Access-Token: forged' -H 'X-Access-Token: forged' https://<import-host>/api/me
```

Each prints a JSON body with `"user"` and then `200`. Both must name you. If the baseline fails, the cookie is wrong and the check proved nothing: fix it first. In the forged request, any `401` is a failure: it shows that the service received the forged value, and answers 401 because the value is not a token. A stronger form forges with a valid token of a second test user, which the administrators can issue for the test: put it in both headers. The answer must still name you. An answer that names the second user means the ingress passes the client's header on.

## Checking that no import runs

**Imports** shows one user's imports. A sync, a backup and a restore concern every user's, so check the records of the whole cluster:

<!-- illustrative -->
```sh
kubectl -n <namespace> exec deploy/sealift -- grep -rlE '"status": "(queued|running)"' /data/imports
```

The check passes when the command prints no path and kubectl ends with `command terminated with exit code 1`, which is grep's answer for no match. Each printed path is an import with a queued or running attempt: wait, and run the command again. An `exit code 2`, a `No such file or directory` line or any kubectl error means the check did not run, and proves nothing.

## Upgrades

1. Take [the backup](#backup-and-restore) of the import's records, and of the collection's volume when the connected side changes.
2. Carry the new image and chart through [Harbor](#from-ghcr-through-the-key-into-harbor).
3. Bump `targetRevision` in `application.yaml` to the new release, and `image.tag` if you pin it.
4. Run [the check](#checking-that-no-import-runs) until it passes.
5. Sync. An import that is running at the sync ends `interrupted`, and a retry continues it.

The connected side changes `SEALIFT_IMAGE` in `.env`, then `docker compose pull && docker compose up -d`. Sessions, archives, settings and the key carry over.

## Backup and restore

Take both when [no import runs](#checking-that-no-import-runs). Take one as well before an upgrade, and before you delete a claim.

The import's records, under `/data/imports`. Count the records, write the backup, and read it back:

<!-- illustrative -->
```sh
kubectl -n <namespace> exec deploy/sealift -- sh -c 'find /data/imports -name import.json | wc -l'
kubectl -n <namespace> exec deploy/sealift -- tar czf - -C /data imports > imports-backup.tgz && echo "backup written"
tar tzf imports-backup.tgz > /dev/null && echo "backup readable"
```

The first command prints the number of records. Both `echo` lines must appear. A missing line, or any error, means the backup is not usable: do not rely on the file.

To restore, use a pod whose `/data/imports` is empty. Restoring over records overwrites them, so check first:

<!-- illustrative -->
```sh
kubectl -n <namespace> exec deploy/sealift -- ls -A /data/imports
```

The command must print nothing. A `No such file or directory` line means the claim is new and empty: that is fine as well. When it lists anything, stop: the pod holds records, and the restore would replace them. Then extract the backup, restart the pod, and count the records again:

<!-- illustrative -->
```sh
kubectl -n <namespace> exec -i deploy/sealift -- tar xzf - -C /data < imports-backup.tgz
kubectl -n <namespace> rollout restart deploy/sealift
kubectl -n <namespace> rollout status deploy/sealift
kubectl -n <namespace> exec deploy/sealift -- sh -c 'find /data/imports -name import.json | wc -l'
```

The restart makes the service read the restored records, and the count must equal the one taken before the backup. The pod runs as user 10000, which owns what it extracts, so no `chown` is needed. The claim itself survives `helm uninstall` and an Argo CD prune.

The collection's volume holds the private key. Check that the volume exists, stop the container, archive the volume, start again, and read the archive back:

<!-- illustrative -->
```sh
docker volume inspect sealift-data > /dev/null && echo "volume found"
docker compose stop sealift
docker run --rm -v sealift-data:/data:ro -v "$PWD":/backup alpine \
  tar czf /backup/sealift-data.tar.gz --exclude=./cache --exclude=./trivy-cache -C /data .
docker compose start sealift
tar tzf sealift-data.tar.gz | grep private/signing-key.pem
```

`volume found` must print first: a missing volume ends with `No such volume`, and a `docker run` on a wrong name creates an empty one and archives nothing. The last command must print the key's path, `./private/signing-key.pem`. Keep that archive as you keep the key.

## Logs

| Side | Command |
| --- | --- |
| Import service | `kubectl -n <namespace> logs deploy/sealift` |
| Collection | `docker compose logs -f sealift` |

## Worst cases on the shared repository

The import publishes into the npm hosted repository that Package Pusher writes to. That repository is production: a package an import publishes is installable at once by every project that reads it. Each worst case has its guard.

| Worst case | Guard |
| --- | --- |
| A wrong archive reaches Nexus | The import writes nothing until the signature verifies with the trusted key, the sha256 you give matches, the archive's sha256 and size match the manifest, and each tarball matches its manifest entry. Fill `Expected sha256 (optional)` on every import into this repository, with the sha256 you received by [another channel](#values-that-cross-by-another-channel) |
| A version Nexus holds is replaced | The import reads each version before its upload and fails one held with other bytes (kind `conflict`), and reads it back after and fails one Nexus serves with other bytes (kind `nexus`). The repository allows redeploy and the request asks no change, since Package Pusher republishes there |
| A race with Package Pusher | Never start a Package Pusher publish into the repository while an import is queued or running, for any user: [the check](#checking-that-no-import-runs) covers the whole cluster. A version uploaded by both tools between the import's check and its upload leaves the last writer's bytes. **Imports** and an import's panel show `Queued` and `Running`: [Importing](importing.md#imports) |
| A partial publish | An attempt that ends `Incomplete` keeps what it published, the archive and its manifest in MinIO, and its records. A project whose lockfile names a missing package cannot install until a retry ends `Complete`. The next step is the retry, which uploads only what Nexus lacks, never a removal |
| A newer `latest` | See below |
| A rollback | See [the rollback list](#the-rollback-list) |

### The `latest` tag

The import writes no dist-tag. It uploads tarballs through Nexus's component upload and nothing else. A lab run on 2026-11-19 on Nexus 3.96.5 showed what Nexus does with `latest` on such an upload: uploading 2.0.0, then 1.0.0, then 1.5.0 kept `latest` at 2.0.0; a prerelease 3.0.0-beta.1 kept it at 2.0.0; a newer stable 2.1.0 moved it to 2.1.0. So an upload never moves `latest` backward or to a prerelease, and moves it forward when it carries a newer stable version than the repository holds. A bare `npm install <name>` then gets that version. An install from a lockfile or a range does not change. The run did not cover `npm publish`, which Package Pusher uses.

Where the target Nexus is another version, this is not proven there. Before the first import, run the check on a hosted npm repository other than the shared one. Three choices keep it from touching production:

- The repository `<test-repository>` is in no group. A group that serves it would hand the probe to every project that reads the group.
- The package is named `@sealift-probe/latest-check`, a scoped name that no registry in front of Nexus can hold, so nothing real can answer for it.
- The account `<probe-user>` is an administrator's or a probe account of its own, never the import's user, whose credential must not leave the service.

Upload the probe at `2.0.0`, `1.0.0`, `1.5.0`, `3.0.0-beta.1` and `2.1.0` in that order, and read the tag after each upload. `ca.pem` is the authority bundle of the values. `curl` asks for the password each time:

<!-- illustrative -->
```sh
mkdir probe && cd probe
for v in 2.0.0 1.0.0 1.5.0 3.0.0-beta.1 2.1.0; do
  printf '{"name":"@sealift-probe/latest-check","version":"%s"}\n' "$v" > package.json
  npm pack --silent
  curl --cacert ../ca.pem -s -o /dev/null -w 'upload %{http_code}\n' -u <probe-user> \
    -F "npm.asset=@sealift-probe-latest-check-$v.tgz" \
    "<nexus-url>/service/rest/v1/components?repository=<test-repository>"
  curl --cacert ../ca.pem -s -u <probe-user> "<nexus-url>/repository/<test-repository>/@sealift-probe%2flatest-check" \
    | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>console.log(JSON.parse(d)["dist-tags"]))'
done
```

Each round prints `upload 204`, then the tags. Any other code is a failed upload: stop. A JSON error, `undefined` or a missing line means the read failed, and the round proved nothing. The tags must read `{ latest: '2.0.0' }` after the first four uploads (2.0.0, 1.0.0, 1.5.0 and 3.0.0-beta.1) and `{ latest: '2.1.0' }` after the last. Then delete the component `@sealift-probe/latest-check` in Nexus under **Browse**, and the folder `probe`.

### The rollback list

sealift holds no delete right in Nexus, and this kit adds no route to delete. A rollback is an administrator's act, from a list that the import's records give. The list holds, for one import, every package that any of its attempts published, as `name@version`. It never holds a package that was only `present`, which Nexus held before the import and which may be Package Pusher's. It lists apart the packages that may have landed: a package that failed with the kind `interrupted`, `nexus` or `local`, a package left pending, and a failure with no kind. `local` is a failure on the import's own side, such as the read-back after an upload, so the upload may have happened. A third list holds the packages that never reached an upload.

The records sit under `/data/imports/<user>/<id>/import.json`. The script reads one record and writes nothing:

<!-- illustrative -->
```sh
kubectl -n <namespace> exec deploy/sealift -- ls /data/imports/<user>
kubectl -n <namespace> exec -i deploy/sealift -- node - /data/imports/<user>/<id>/import.json < sealift/files/published.mjs
```

The output has three parts:

| Part | What it holds |
| --- | --- |
| `Published by this import:` | One `name@version` per package that an attempt uploaded |
| `Possibly published, check each in Nexus first:` | Each package that may have landed, followed by one line for every attempt that touched it, in the form `attempt <n>: state=<state> kind=<kind> reason=<reason> started=<time> ended=<time>`, with `-` for a value the record does not hold |
| `Never uploaded, nothing to remove:` | Each package whose every attempt failed before any upload: the reason starts with `repository check failed:`, or the kind is `conflict`, `mismatch` or `source` |

The script prints all three headings every time; a heading with nothing under it is empty. An import that ended `Complete` can still list a package under `Possibly published` when one of its attempts failed it before a later attempt found it present. A line `<path> is not an import record` on stderr, or a usage line, means the path is wrong and nothing was listed.

Steps for the administrator:

1. For each package under `Published by this import:`, decide whether it must go, and read its asset in Nexus as step 2 says before you delete it: another tool can have replaced the version since. Deleting a version breaks any project that installed it.
2. For each package under `Possibly published`, check in Nexus before you delete anything. Such a package may be one that Package Pusher published. Open the component in Nexus under **Browse** and read its asset. Both must hold: the uploader is the sealift publisher user, and the upload time falls between the start and the end of one of the attempt lines listed for that package. When either fails, leave the component.
3. Leave every package of the third part. Its attempts never reached an upload, so a version Nexus holds under that name was never this import's. Delete nothing there.
4. Before you delete a version, list the other imports whose records name the package:

   <!-- illustrative -->
   ```sh
   kubectl -n <namespace> exec deploy/sealift -- grep -rl '"name": "<name>"' /data/imports
   ```

   Each path is an import that carries that package, possibly at that version, this import included. Any of them that did not end `Complete` publishes the version again on its next retry, or on a new start of its archive, because an upload sends every version Nexus lacks. So, for a version you remove because it is bad: before you delete it, have each such archive removed from its user's MinIO folder, or tell its users not to retry or start it again. An import that ended `Complete` has no archive left to publish from; its users need a fresh export, imported again, if they still need a good version.
5. In Nexus, open **Browse**, select the repository, find the component, select **Delete component**, and confirm. The same is available through the REST API as `DELETE /service/rest/v1/components/<component-id>` for a user with the delete privilege.
6. Record what you deleted.

What a deletion does to `latest` and to the package's metadata is not proven in the lab. A package found bad after the import goes through the same list.
