// =============================================================================
// ESLint flat config — applies to web/ only.
// =============================================================================
// PRD: FR-L.41 (eslint).
// =============================================================================

import js from "@eslint/js";
import prettier from "eslint-config-prettier";

export default [
  {
    ignores: ["dist/**", "coverage/**", "node_modules/**"],
  },
  js.configs.recommended,
  prettier,
  {
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "module",
      globals: {
        crypto: "readonly",
        window: "readonly",
        document: "readonly",
        TextEncoder: "readonly",
        TextDecoder: "readonly",
        // reveal.js: session clock and clipboard purge timer.
        performance: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
      },
    },
    rules: {
      // FR-A NFR — only Math.random() is forbidden; Math.floor/round/log2 etc.
      // are allowed and necessary in the entropy and generator code.
      "no-restricted-syntax": [
        "error",
        {
          selector: "MemberExpression[object.name='Math'][property.name='random']",
          message:
            "Math.random() is forbidden — use cryptoRandomInt / cryptoRandomBytes from src/crypto.js (FR-A NFR).",
        },
      ],
      eqeqeq: ["error", "always"],
      "no-var": "error",
      "prefer-const": "error",
    },
  },
];
