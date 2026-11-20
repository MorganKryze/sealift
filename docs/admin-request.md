# Request to the administrators

This page is a request that you can forward once the `<name>` values are replaced. It asks for the accounts and the infrastructure that the sealift import service needs on the air-gapped side, with the reason for each and what fails without it. It asks for nothing sealift does not use. [The runbook](runbook.md) is the install that follows.

sealift's import service lets each signed-in user import an archive from their own MinIO folder into the npm Nexus repository. It checks every archive before it writes anything. Package Pusher keeps running meanwhile: this request adds a hostname and a Keycloak client of its own and changes none of Package Pusher's settings.

## What the service never does

- It never puts an object in MinIO. It reads and deletes under `packages/npm/` only, in the bucket of the signed-in user, and deletes the archive, the manifest and the signature only after the import ended `complete`.
- It never replaces a version that Nexus holds, by its own check. [The next section](#no-change-to-the-deployment-policy) says where that check stops.
- It never writes a dist-tag.
- It never deletes in Nexus.
- It never turns certificate checks off.

## MinIO

Ask for one service user with this policy, verbatim:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": ["arn:aws:s3:::user-*"],
      "Condition": {"StringLike": {"s3:prefix": ["packages/npm/", "packages/npm/*"]}}
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:DeleteObject"],
      "Resource": ["arn:aws:s3:::user-*/packages/npm/*"]
    }
  ]
}
```

Why: the service lists a user's archives, reads them and removes them after a complete import. What fails without it: **Archives** lists nothing or answers with an error, and an import cannot read its archive. Proven in the lab: with this user, `mc` could not put an object, and could not list or read `packages/pip/`, list a bucket's root or list the buckets. The policy covers every `user-*` bucket, and the service itself keeps a request to the bucket of the checked user. Each user needs the bucket `user-<name>`: it already exists for Package Pusher's users.

## Nexus

Ask for one user with a role that holds these five privileges on the existing npm hosted repository, and no others:

- `nx-repository-view-npm-<nexus-repository>-browse`
- `nx-repository-view-npm-<nexus-repository>-read`
- `nx-repository-view-npm-<nexus-repository>-add`
- `nx-repository-view-npm-<nexus-repository>-edit`
- `nx-component-upload`

Why: the service reads a version before it uploads it, uploads the tarball through the component upload, and reads it back. What fails without it: a missing read or browse privilege fails the check of each version, and a missing `add`, `edit` or `nx-component-upload` privilege fails the upload with a 403. Nexus refuses an upload without the edit privilege. Proven in the lab: `lab/setup.sh` creates this role and the import published through it.

### No change to the deployment policy

The request asks for no change to the repository's deployment policy. Package Pusher publishes there and may republish a version, so **Disable redeploy** could break it. The service guards the repository itself: it reads each version before the upload and fails one that holds other bytes, and reads it back after the upload and fails one that Nexus serves with other bytes. The window between the read and the upload stays open to a Package Pusher upload of the same version, so the runbook forbids a Package Pusher publish while an import is queued or running.

The import's credential holds the `add` and `edit` privileges, so on a repository that allows redeploy it can overwrite any version there. Only the service's read before the upload prevents that, and the lab proved that guard only on a repository whose policy was `allow_once`. On a repository that allows redeploy it is not proven. Weigh that before you grant the role on the shared repository, and see the dedicated repository below.

### The `latest` tag

The service writes no dist-tag. A lab run on 2026-11-19 on Nexus 3.96.5 showed that the component upload never moves `latest` backward or to a prerelease, and moves it forward when it carries a newer stable version than the repository holds. A bare `npm install <name>` then gets that version, and an install from a lockfile or a range does not change. Please tell us the Nexus version. The behaviour is not proven on another one, and the runbook gives the check to run on a repository other than the shared one.

### If writes to the shared repository are refused

Ask for a dedicated hosted npm repository for the proof of concept, with the same five privileges, and a group that also serves it to projects. Nothing imported then reaches production, and removing a version needs no administrator.

## Nexus for Python

sealift does not publish Python packages yet: support for pip is in progress. Asking now keeps the request from blocking that upgrade, and the same rights serve the manual path used until then.

Ask for a hosted `pypi` repository, or the existing one, and a role on it with these five privileges, held by the same user as the npm role or by a second one:

- `nx-repository-view-pypi-<nexus-pypi-repository>-browse`
- `nx-repository-view-pypi-<nexus-pypi-repository>-read`
- `nx-repository-view-pypi-<nexus-pypi-repository>-add`
- `nx-repository-view-pypi-<nexus-pypi-repository>-edit`
- `nx-component-upload`

Why: the same as for npm. A wheel is read before its upload, uploaded through the component upload, and read back. What fails without it: the same 403 on the upload, and a failed check on each version without read or browse. Projects install from the repository's simple index, `<nexus-url>/repository/<nexus-pypi-repository>/simple/`, or from a group that serves it. Ask for **Disable redeploy** on a new repository: a wheel never changes once published.

## Keycloak

Ask for one confidential client for the import's oauth2-proxy, in the realm Package Pusher already uses:

| Setting | Value |
| --- | --- |
| Client id | `<keycloak-client-id>` |
| Valid redirect URI | `https://<import-host>/oauth2/callback` |
| Web origin | `https://<import-host>` |
| PKCE | method S256 |
| Standard flow | on |
| Direct access grants | off |
| Audience mapper | adds the client id to the access token's `aud` claim |
| Username | users cannot edit `preferred_username`, and it is unique in the realm |

Why: oauth2-proxy signs users in and passes the access token. The service compares the token's `iss` and `aud` with its settings and checks its signature against the realm's keys. What fails without it: a 401 naming `audience` or `issuer` on every call. Proven in the lab: the client with PKCE S256, standard flow and the audience mapper. The lab's client leaves direct access grants on for its scripts, so turning it off is not proven. The service names a user's bucket and folder from `preferred_username` alone, so a user who can edit that claim could act as another user: please turn editing of the username off in the realm. We suggest a group of the people who may import, admitted in oauth2-proxy with `--allowed-group`, so that any other realm user is refused before the service. That needs the group claim in the token. Please send the realm's address and the client secret through your usual channel for secrets.

## Infrastructure

Ask for these items where you do not already hold them:

| Item | Why | What fails without it |
| --- | --- | --- |
| A namespace `<namespace>` | The chart installs there | Nothing installs |
| A hostname `<import-host>` with its TLS certificate | The service and its screens serve at `/` of a host of their own | Users cannot open the screens, and the sign-in cookie has no host |
| A storage class | The import's records need a persistent volume | The records are lost at each pod replacement |
| A Harbor project `<harbor-project>`, with a robot account that pushes and one that pulls | The image and the chart cross the USB key into Harbor | The cluster cannot pull the image or the chart |
| Network access from the namespace to Keycloak, MinIO and Nexus | The service calls the three | The pod starts and every call fails |
| The name of the ingress controller's namespace | The NetworkPolicy admits that namespace only | The ingress cannot reach the pod, with timeouts |
| A scratch hosted npm repository `<test-repository>` that no group serves, and an account `<probe-user>` that writes there | The `latest` check uploads a probe package, and must not touch the shared repository | The check runs on production or does not run |
| Whether the cluster's network plugin enforces NetworkPolicy | The policy keeps other pods from calling the service around the sign-in | Any pod can call the service, which still checks every token |
| The Nexus version | The `latest` behaviour is proven on 3.96.5 only | The check on another version is left to the runbook |
| Whether ingress-nginx refuses ExternalName backends and snippet annotations | An Ingress that a user of the cluster writes could route traffic to the service around the sign-in | The service still checks every token, but a client then chooses the header's value |
| Write access to the values repository, limited to a few reviewers and reviewed on `main` | The values name the key the service trusts and the addresses it sends credentials to | Anyone who writes there redirects them |

None of these was proven in the lab, which has no Kubernetes, no Harbor and no ingress controller. The ingress-nginx annotations that the install uses are not proven in the lab either: their first run is the install. A plain Kubernetes Secret holds the Nexus password and the MinIO keys, so please restrict the right to read Secrets in the namespace. The TLS Secret of `<import-host>` sits there too, and a copy of it in oauth2-proxy's namespace: restrict both.
