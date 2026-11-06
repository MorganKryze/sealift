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
    },
  },
  {
    // The import role's screens reach nothing of the collection and render no markup from the API's text.
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
                "@/components/setup-screen",
                "@/components/step-bar",
                "@/components/severity-counts",
                "@/hooks/use-job-events",
              ],
              message: "The import screens share only the ui, brand, theme toggle, return-focus and utils modules with the collection.",
            },
          ],
        },
      ],
      "no-restricted-syntax": [
        "error",
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message: "Text from an archive, a manifest, MinIO or Nexus renders as a text node.",
        },
      ],
    },
  },
)
