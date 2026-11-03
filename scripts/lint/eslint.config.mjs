// ESLint for the scripts inside the companion's pages, run by ./scripts/dev.
// Correctness rules only: formatting belongs to Prettier (npm run format:web).
import js from "@eslint/js";
import html from "eslint-plugin-html";
import globals from "globals";

export default [
  {
    files: ["**/*.html"],
    plugins: { html },
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "script",
      globals: globals.browser,
    },
    linterOptions: { reportUnusedDisableDirectives: "error", noInlineConfig: true },
    rules: {
      ...js.configs.recommended.rules,
    },
  },
];
