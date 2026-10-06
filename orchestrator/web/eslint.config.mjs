import { readFileSync } from 'node:fs';
const browser = JSON.parse(readFileSync(new URL('./eslint-browser-globals.json', import.meta.url), 'utf8'));

// A local declaration that reuses an imported name silently redirects every
// use in its scope away from the import -- this is how the Live Run drawer's
// own `var state` hid core/state.js (G1c final review, Critical 1).
const noShadowImport = {
  meta: { type: 'problem', schema: [] },
  create(context) {
    return {
      'Program:exit'(node) {
        const scopes = context.sourceCode.scopeManager.scopes;
        const moduleScope = scopes.find((s) => s.type === 'module');
        if (!moduleScope) return;
        const imported = new Set(moduleScope.variables.filter((v) => v.defs.some((d) => d.type === 'ImportBinding')).map((v) => v.name));
        for (const scope of scopes) {
          if (scope === moduleScope || scope.type === 'global') continue;
          for (const v of scope.variables) {
            if (imported.has(v.name) && v.defs.length) {
              context.report({ node: v.defs[0].name, message: `'${v.name}' shadows an imported binding; rename the local.` });
            }
          }
        }
      },
    };
  },
};

export default [
  {
    files: ['src/**/*.js'],
    languageOptions: { ecmaVersion: 2022, sourceType: 'module', globals: browser },
    plugins: { local: { rules: { 'no-shadow-import': noShadowImport } } },
    rules: {
      'local/no-shadow-import': 'error',
      'no-undef': 'error',
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-import-assign': 'error',
      'no-restricted-properties': ['warn',
        { property: 'innerHTML', message: 'innerHTML sink: gated by the G1 guard.' },
        { property: 'outerHTML', message: 'outerHTML sink.' },
        { property: 'insertAdjacentHTML', message: 'insertAdjacentHTML sink.' },
        { object: 'document', property: 'write', message: 'document.write sink.' },
      ],
    },
  },
];
