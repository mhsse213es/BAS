import { readFileSync } from 'node:fs';
const browser = JSON.parse(readFileSync(new URL('./eslint-browser-globals.json', import.meta.url), 'utf8'));

export default [
  {
    files: ['src/**/*.js'],
    languageOptions: { ecmaVersion: 2022, sourceType: 'module', globals: browser },
    rules: {
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
