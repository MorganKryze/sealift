// A crossing at its own address, at each step its seeded state reaches, then Ready to seal. The selection
// and the reasons are written to sessionStorage before the page loads, as the review keeps them there.
// The earlier session addresses land on their crossing: a state at one of them waits for a text only the
// crossing draws.

const stored = (storage) => (page) =>
  page.addInitScript((entries) => {
    for (const [key, value] of Object.entries(entries)) sessionStorage.setItem(key, JSON.stringify(value))
  }, storage)
const button = (name) => ({ role: "button", name })

// reasons: html-minifier keeps a CVE no version fixes, so one written reason makes it Ready.
const readyReasons = stored({
  "sealift:reasons:20261124T101500Z": { "cve-without-fix:html-minifier": "Dev dependency, runs at build time on our own HTML" },
})

// worst: 15 major jumps in 3 families and 15 CVEs with no fix in 5 packages, every reason written.
const WORST_SELECTION = {
  react: ["19.2.0"], "react-dom": ["19.2.0"], "@types/react": ["19.2.2"], "@types/react-dom": ["19.2.2"], "react-router-dom": ["7.9.4"],
  "@testing-library/react": ["16.3.0"], "react-redux": ["9.2.0"], eslint: ["9.38.0"], "eslint-plugin-react-hooks": ["5.2.0"],
  "@typescript-eslint/parser": ["8.46.1"], "@typescript-eslint/eslint-plugin": ["8.46.1"], "eslint-config-prettier": ["10.1.8"],
  vite: ["7.1.12"], "@vitejs/plugin-react": ["5.1.0"], vitest: ["4.0.8"],
}
const worstReady = stored({
  "sealift:selection:20261125T091500Z": WORST_SELECTION,
  "sealift:reasons:20261125T091500Z": {
    "major-jump:react 19": "Moved to React 19 in branch react-19, all tests green",
    "major-jump:eslint 9": "Flat config done in PR #412, lint passes on main",
    "major-jump:vite 7": "CI and every dev machine run Node 22; Vite 7 builds the app",
    "cve-without-fix:angular": "Pinned by the legacy kiosk, which leaves with the Q3 rewrite; no user input reaches its templates",
    "cve-without-fix:html-minifier": "Dev dependency, runs at build time on our own HTML",
    "cve-without-fix:lodash.template": "Templates are our own files, never user input",
    "cve-without-fix:@babel/plugin-transform-async-generator-functions": "Build only, never in the bundle",
    "cve-without-fix:request": "Called once at deploy time against our own host",
  },
})

const SEVERITY_TEXT = "Each CVE is rated critical, high, medium or low by the harm it can do, or unknown when it has no rating. Versions are ranked by these counts, the most serious first."

export const states = [
  { path: "/crossings/reasons", name: "ready to seal", before: readyReasons, ready: "Ready to seal" },
  { path: "/crossings/reasons", name: "ready with a group open", before: readyReasons, click: [button(/^1 package updated/)], ready: "Ready to seal" },
  { path: "/crossings/reasons", name: "ready with the severity explanation open", before: readyReasons, click: [button("What a severity is")], ready: SEVERITY_TEXT },
  { path: "/crossings/worst", name: "ready, the worst case", before: worstReady, click: [button("7 packages of react 19"), button("11 CVEs of angular")], ready: "Ready to seal" },
  { path: "/crossings/demo?step=check", name: "check read back", ready: "Update demo" },
  { path: "/crossings/demo?step=review", name: "review gone back to", ready: "Ready to seal" },
  // Its crumb: the browser's en-GB writes September "Sep" or "Sept" by its version.
  { path: "/crossings/demo", name: "sealed", ready: /^demo · 21 Sept?$/ },
  { path: "/crossings/legacy", name: "an analysis 0.7.0 wrote", ready: "One thing needs you" },
  { path: "/crossings/legacy?step=check", name: "check read back for 0.7.0", ready: "Update legacy-portal" },
  { path: "/crossings/web-portal", name: "its latest analysis failed", ready: "web-portal · 23 Nov · 2" },
  { path: "/crossings/web-portal?analysis=20261118T101500Z", name: "an earlier analysis cancelled", ready: "Analysis cancelled" },
  // The earlier export, signed by 0.7.0 with no review, opened by naming its analysis.
  { path: "/crossings/web-portal?analysis=20261123T091500Z", name: "an earlier crossing sealed by 0.7.0", ready: "web-portal · 23 Nov" },
  // The session pages drew the package.json under the project's name and an analysis whatever its state.
  { path: "/sessions/demo/drop", name: "an earlier check address", ready: "Update demo" },
  { path: "/sessions/demo/review", name: "an earlier review address", ready: "Ready to seal" },
  { path: "/sessions/web-portal/analysis?analysis=20261123T091500Z", name: "an earlier analysis address naming its analysis", ready: "web-portal · 23 Nov" },
]
