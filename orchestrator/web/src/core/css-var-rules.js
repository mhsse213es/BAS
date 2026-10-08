// Registry of data-driven declarations (G1e spec 4.4). Maintained by
// tools/g1e-codemod.mjs --split; keys sorted. Each rule is one declaration:
// prop, value template with {0}..{n} placeholders, and one type per placeholder.
export const CSS_VAR_RULES = {
  'g1-v-7d75dfc9': {"prop":"color","value":"{0}","types":["color"]},
  'g1-v-9b890877': {"prop":"width","value":"{0}%","types":["integer"]},
  'g1-v-9ffd39ba': {"prop":"background","value":"{0}","types":["color"]},
  'g1-v-bd5c5d10': {"prop":"background","value":"conic-gradient({0} {1}%, var(--elevated) 0%)","types":["color","integer"]},
};
