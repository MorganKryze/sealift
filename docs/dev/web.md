# Web

This page covers the React interface in `web/`: its routes, the step bar, how screens follow a running job, and how to check a screen in a real browser. [Contributing](../../CONTRIBUTING.md#run-it-locally) shows how to run it.

## Stack

React 19 with TanStack Router and TanStack Query, Tailwind CSS 4, components from shadcn/ui in `web/src/components/ui/`, Vitest with jsdom for tests. The build goes to `web/dist/app`, which the Go binary embeds. Routes are not code-split: the interface ships as one bundle, so a click never waits for the server to send a screen.

The API types in `web/src/api/schema.d.ts` are generated from `api/openapi.yaml` by `pnpm -C web run generate`, which `just generate` also runs. Never edit that file by hand. `web/src/api/client.ts` wraps `fetch`: a response that is not 2xx throws a `ProblemError` carrying the problem body, and a request that never reaches the server throws the `UNREACHABLE` problem, shown as sealift is not reachable.

## Routes

File-based, in `web/src/routes/`:

| Route | Screen |
| --- | --- |
| `/` | Setup when a tool or the key is missing, otherwise home: the drop zone, the drop preview, past sessions |
| `/settings` | Opens the settings panel over home |
| `/sessions/$sessionId` | Redirects to the session's most useful step: export when an archive exists, review after a finished analysis, analysis otherwise |
| `/sessions/$sessionId/drop` | The manifest the session started from |
| `/sessions/$sessionId/analysis` | The nine steps, the counter, the failure block |
| `/sessions/$sessionId/review` | The proposal and the selection |
| `/sessions/$sessionId/export` | The export progress and the archive |

A dropped file has no route until the session exists: the drop preview is state on the home screen, and **Analyse** creates the project.

## The step bar

`web/src/lib/sessionSteps.ts` computes the four steps from the project's latest analysis and the latest export of that analysis. Each step is `upcoming`, `available`, `running`, `done` or `failed`, and one is `current`. A failed, cancelled or interrupted analysis marks Analyse as failed. Review turns done only once an export exists. Every route renders the bar from this one function, so the rule lives in one place; `sessionSteps.test.ts` covers it.

## Following a running job

`web/src/hooks/use-job-events.ts` opens one `EventSource` on `/api/jobs/current/events`. The server names each frame after its kind, so the hook listens for `step`, `progress`, `candidate`, `log` and `end` one by one; a plain `onmessage` would receive nothing. It keeps the events whose `storeId` matches the id on screen and folds them into state with a reducer. On `end`, it calls the screen's `onEnd`, which refetches the project, so the screen reads the final state from the API. It sets no `onerror`: `EventSource` reconnects by itself after the server closes a finished stream, and the project queries poll as a fallback.

Two rules keep the screens steady while events arrive several times a second:

- Within one run, the nodes that show progress stay mounted. Only their props change. `Progress` in `components/ui/progress.tsx` is a plain element for that reason. A remount per tick makes the bar and the counter flicker.
- Across runs, the screen remounts. The analysis route renders `<AnalysisScreen key={analysis.id}>`, so a retry starts from a fresh reducer instead of showing the previous run's failed steps. `use-job-events.test.ts` documents both cases.

## The review selection

`web/src/hooks/use-selection.ts` holds the version chosen for each dependency, starting from `best`, and keeps it in `sessionStorage` so a reload does not lose it. `web/src/lib/reviewGroups.ts` sorts dependencies into To decide, Proposed and Nothing to do from sealift's proposal, not from the selection, so a row does not move while someone picks a version. `web/src/lib/exportSelection.ts` turns the selection into the export request; a retried export sends the same selection. [Ranking](ranking.md#the-review-groups) gives the grouping rule.

## The settings panel

`components/settings/settings-panel.tsx` renders a side sheet over the current screen, from anywhere, and returns focus to what opened it. `settings-form.tsx` holds the form: the platform choice from `lib/platforms.ts`, the Node version checked as you type, the key with Replace and Clear, the limits with their ranges. `PUT /api/settings` replaces every field, so the form always sends the full object, with `********` to keep the saved key. `tools-panel.tsx` holds the Trivy, database and pnpm cards.

## Checks

```sh
pnpm -C web run typecheck
pnpm -C web run lint
pnpm -C web run test
```

`just web-check` runs all three. Tests sit next to the code they cover, as `*.test.ts` and `*.test.tsx`.

## Checking a screen in a browser

A unit test does not show that a screen renders the right thing once the real server answers. Before calling a screen done, drive it in a real browser against a real server, with Playwright or puppeteer:

- Start the server on a scratch data directory, and either `vite dev` or a production build served by the binary.
- Wait for the content you expect, such as a heading or a button label. Never wait for network idle: the event stream stays open, so the network never goes idle.
- Check the running, failed, cancelled and reloaded states, not only the finished one, and both themes.
- To check that a progress element does not remount, keep a reference to the node and assert that it is the same node after a few events, or watch its parent with a `MutationObserver` and count `childList` changes during a run:

```js
const bar = document.querySelector('[role="progressbar"]')
let swaps = 0
new MutationObserver((records) => {
  swaps += records.filter((r) => [...r.removedNodes].includes(bar)).length
}).observe(bar.parentElement, { childList: true })
// after the run: swaps must be 0, and document.contains(bar) true
```

A screenshot alone proves only that something rendered.
