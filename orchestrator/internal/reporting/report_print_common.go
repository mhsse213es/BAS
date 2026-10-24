package reporting

// reportSharedPrintCSS is print behaviour shared by the non-BAS report
// templates (exercise, compliance, AD assessment). Each template inserts this
// block at the start of its own <style> element, so its own rules still come
// after it and can override any of these.
//
// Deliberately narrow. Each rule here was checked against a rendered compliance
// report, and the broader rules from the main BAS report (html.go) are NOT
// shared, because they changed the page count:
//   - table-layout:fixed pushed the compliance cover onto a second page.
//   - Page-flow changes (page-break-after:auto) depend on the cover being the
//     first child element, which these templates do not guarantee.
//   - Hiding the .ph/.pf page bars would change the exercise report, which
//     prints them on purpose.
//
// Rules:
//   - Cell text wraps, so a long word cannot push a table wider than the page.
//   - Cards are not split across a page break.
//
// Contains no backticks, because it is spliced into Go raw string literals.
const reportSharedPrintCSS = `
@media print{
  th,td{overflow-wrap:anywhere}
  .fc,.scard,.gloss-item,.exec-card,.ctrl{page-break-inside:avoid;break-inside:avoid}
}
`
