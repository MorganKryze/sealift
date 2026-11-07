# Importing

This page covers the three screens of `sealift import-server`, the import service on the air-gapped side: Archives, Imports and one import. The service publishes the npm packages of an archive to Nexus. Each user sees their own archives and imports and no one else's.

Sign in through your organisation's gateway and open its address. The header names the screens, `Archives` and `Imports`, your user name and `Settings`. The Settings sheet holds `Appearance` (the theme, saved in this browser only) and `Your MinIO folder`, the `Bucket` and `Folder` the service reads your archives from.

## Archives

![Archives, with two archives that cannot be imported, one that can, and one whose import ended incomplete](assets/import-archives.png)

Archives lists the archives in your MinIO folder, newest first: `packages/npm/` in your bucket, and one folder below it. The line under the title counts them, such as `5 archives · 2 importable`. `All` and `Importable` filter the rows, and `Refresh` reads the folder again. The list also reads again each time you open the screen.

An archive can be imported when its folder holds one archive and its `manifest.json`, side by side. Any other row says `Cannot be imported` and why:

| Reason on the row | What to do |
| --- | --- |
| `its name cannot be imported` | Rename or move it: the key must end in `.tar.gz`, sit in `packages/npm/` or one folder below it, hold no empty, `.` or `..` segment and no control character, and stay within 1,024 bytes. |
| `the folder holds more than one archive` | Keep one archive and its manifest.json in the folder. |
| `no manifest.json in its folder` | Upload the manifest next to the archive. |

An importable row says `Can be imported`, then one of these:

- `Not imported yet` and the `Start` button.
- The state of the latest import of this archive, with its counts, and `Open import`. While that import is queued or running, the row says `Waiting its turn` or the packages done so far, and the link reads `Follow`.
- For a complete import whose archive is still listed, why it stayed: `Removal not recorded yet.`, or `Kept in MinIO:` and the reason.

Two notices can sit above the rows. One says the folder holds more than 1,000 objects and the list shows the first 1,000 in name order. The other says that the links to the key set, MinIO or Nexus run over plain http, so package contents and credentials cross the network unencrypted there.

An empty list says `No archive in your folder` and where to upload. `MinIO is not configured` means the administrator has not set the `minio` section of the settings file.

### Start an import

`Start` opens a panel under the row. It says what the import does and that imports run one at a time for every user, so yours may wait its turn. The field `Expected sha256 (optional)` takes the archive's sha256 as you received it through another channel. A value that is not 64 hexadecimal digits is refused on the spot. A different archive is refused after it is read, and nothing is published. `Start the import` begins, `Cancel` closes the panel, and Escape closes it too.

If the archive already has an import that has not completed, the panel says `This archive has an import that has not completed.` and sends you to follow or retry that one. If the archive left your folder meanwhile, it says `This archive is no longer in your folder.`

## Imports

Imports lists every import you started, newest first, with its state, its attempt and its counts of `published`, `present` and `failed` packages. A row that ended `incomplete` says how many packages are not in Nexus and sends you to its retry. `No import yet` is the empty list. While an import is running or queued, the list says `One import runs at a time; the others wait in the order they were started.` and updates every 5 seconds.

## One import

An import shows the archive's name and folder, its state, the settings it ran with (the attempt number, the start, the archive size, the Nexus repository and address, the target platform and the Node and pnpm versions), and a notice when Nexus, MinIO or the key set is reached over plain http.

### States

| State | Meaning |
| --- | --- |
| `Queued` | Waiting its turn. The panel says `Waiting its turn`. |
| `Running` | Going through its stages, see below. |
| `Complete` | Every package is in Nexus. |
| `Incomplete` | At least one package failed. |
| `Refused` | A check failed before the first package. |
| `Interrupted` | The service stopped before the attempt ended. |
| `Not recorded` | A record that names no state this version knows. |

While it runs, one panel shows the stage and stays in place: `Waiting its turn`, `Reading the manifest`, `Checking the archive` (the check reads the whole archive once and shows no byte progress, so a large archive can take minutes) and `Publishing packages: 37 of 101` with a bar and the counts `published`, `present`, `failed` and `pending`. The page updates every 2 seconds. When the attempt ends, the panel reads `Attempt 1 ended: Complete`, or the state that applies.

![A running import, publishing packages: 37 of 101](assets/import-running.png)

### How an attempt ends

| Card | When | What it says |
| --- | --- | --- |
| `Archive removed from MinIO` | `Complete`, the removal recorded | `All 101 packages are in Nexus: 0 published, 101 present.` Both objects were removed after each still carried the ETag the import read. The card shows `Archive ETag` and `Manifest ETag`. |
| `Archive removed from MinIO, manifest kept` | `Complete`, the manifest could not go | The reason follows. |
| `Archive kept in MinIO` | `Complete`, the removal failed or was refused | The reason, and a `Retry import` button. |
| `Checking the archive's removal` | `Complete`, no removal recorded yet | The page updates until the service records it. |
| `Refused before the first package` | `Refused` | The reason, such as both digests when the expected sha256 differs. `This attempt published nothing and read no package.` and `Go to archives`. Starting the archive again is allowed. |
| `Stopped before it ended` | `Interrupted` | `The service stopped or restarted before this attempt ended.`, how many packages were finished and how many were not. |

The words `complete` and `removed` appear only when the record says so. The `Archive sha256 check` block says `The archive matched: it passed its checks against the manifest and the signature key.` only when the attempt recorded that the checks passed, and `The archive has not passed its checks.` when it recorded that they did not. An attempt that has not reached the checks yet, because it is queued or running before the manifest is read, says `The archive's checks have not run yet.` An attempt that ended with no check result, such as one interrupted while it waited or a record written by 0.4.0, says `Not recorded: this attempt did not record the archive's checks.` A package of a 0.4.0 record has no kind, and its next action is the general one: `Read the reason: it names what failed. Fix that, then retry.`

The `Archive sha256 check` block shows `Expected sha256` (`No expected sha256 was given.` when you gave none) and `Manifest sha256`, each with a `Copy` button. Where the browser offers no clipboard, which is the case on a page served over plain http from any name other than `localhost`, the button selects the text and says `The clipboard is not available on this page. The text is selected: press Ctrl+C, or Command+C on a Mac, to copy it.`

### The retry card

An `Incomplete` import shows a card titled `1 of 101 packages are not in Nexus`. It lists what a retry does: it adds an attempt, reads the archive and its manifest from MinIO again and checks the sha256 again, reads every package from Nexus again, says how many are there already and stay untouched, uploads only what Nexus lacks and removes the archive only once every package is in Nexus. The card sorts the failures by what they need:

| Group | Kinds |
| --- | --- |
| `Can succeed on retry` | `interrupted`, `source`: retry as it is. |
| `Fails again until fixed outside sealift` | `conflict`, `mismatch`, `nexus`, `local`, each with its count and its words. |
| `Cause not recorded` | A package with no kind, or one this version does not know. |

For a `conflict`, the card says `Nexus holds this version with other bytes, and sealift never overwrites it. If that copy is the wrong one, delete it in Nexus, then retry.` The retry button is `Retry import`. If the service refuses it, the card says `The retry was refused` and why. Earlier attempts stay listed under `Earlier attempts`.

![An incomplete import with its retry card and the failed package](assets/import-incomplete.png)

### Packages

`Packages` is a table with the columns `Package`, `State` and `Detail`. It lists each package of the attempt with its state, `Published`, `Present` (Nexus already held the same bytes), `Failed`, `Not finished`, `Pending` or `Not recorded`. A failed row is tinted and its detail gives the reason, then `Next:` and what to do. `All` and `Failed` filter the list. A long reason is cut: `Show full reason` opens it. An import that ends with failures opens on `Failed`.

## When your session ends

The gateway signs users out after a time. A screen that finds itself signed out says `Your session has ended` and `The page was signed out while you were away. Sign in again to carry on; nothing you started was changed.` with `Sign in again`. The notice replaces a list that was on screen, along with its count line and its `Refresh` button. Imports go on without the page.

An error page from the gateway is not a sign-out. While the service restarts, nginx answers with its own HTML page and status 502 or 504. A screen reads that as a failed request: a list on screen stays, with `The last refresh failed. The list is as it was.` next to its count, and a screen with nothing to show says `This could not be loaded` with `Try again`.

## Checked in the lab

The screens above were read on the lab's gateway at http://localhost:18440 (see `lab/README.md`), signed in as `alice` and `bob`, in a browser driven by script, against an image built from this branch, and the captures come from that run. The run covered:

- Archives with five rows: two in a folder holding two archives, one in a folder with no manifest, one not imported yet and one whose import ended incomplete. Archives while one import ran and another waited, with the `Follow` links.
- Imports, with imports of every state the lab held, and each of these on its own page: a complete import with the archive removed, an incomplete one with a planted conflict, a refused one, a running one at 37 of 101 packages, a queued one and an interrupted one after `docker compose restart import-server`. The queued import read `The archive's checks have not run yet.` and, once the restart had interrupted it before it started, `Not recorded: this attempt did not record the archive's checks.`
- The session ending: deleting the `_oauth2_proxy` cookie and pressing `Refresh` on Archives, and opening Imports from an import page, each replaced the list with `Your session has ended`.
- A stopped `import-server`: the gateway answered `/api/imports` with a 502 `text/html` page, and the running import's page kept its panel and never said `Your session has ended` over 26 seconds. A 502 HTML answer to the Archives `Refresh`, served by the script, left the 10 rows in place with `The last refresh failed. The list is as it was.`
- `bob` saw none of alice's archives or imports, and her import's address answered `No such import` to him.

Not driven in the lab this time: the cards for a kept archive and a removal not yet recorded, a retry, an import that was refused after an incomplete attempt, and the clipboard fallback of `Copy`. The unit tests and the browser gate's fixtures cover the cards and the wording.
