import js from "@eslint/js"
import reactHooks from "eslint-plugin-react-hooks"
import globals from "globals"
import tseslint from "typescript-eslint"

export default tseslint.config(
  { ignores: ["dist", "src/routeTree.gen.ts", "src/import/routeTree.gen.ts"] },
  {
    files: ["**/*.{ts,tsx}"],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
    plugins: {
      "react-hooks": reactHooks,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // Text from an archive, a manifest, the API, MinIO or Nexus renders as a text node, on every screen.
      "no-restricted-syntax": [
        "error",
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message: "Text from an archive, a manifest, the API, MinIO or Nexus renders as a text node.",
        },
      ],
    },
  },
  {
    // The import role's screens reach nothing of the collection.
    files: ["src/import/**/*.{ts,tsx}", "src/components/import/**/*.{ts,tsx}"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: [
                "@/api/*",
                "@/routes/*",
                "@/components/session/*",
                "@/components/settings/*",
                "@/components/projects/*",
                "@/components/nav",
                "@/components/failure-block",
                "@/components/problem-notice",
                "@/components/route-error",
                "@/components/preparing-screen",
                "@/components/step-bar",
                "@/components/severity-counts",
                "@/hooks/use-job-events",
              ],
              message: "The import screens share only the ui, brand, copy control, theme toggle and utils modules with the collection.",
            },
          ],
        },
      ],
    },
  },
)
