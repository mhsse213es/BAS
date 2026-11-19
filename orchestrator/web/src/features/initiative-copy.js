// Plain-language text for the Initiatives page. Kept in one pure module so the page, the empty states and the tests
// read the same words. Every button or menu item named here must exist in the app (see tests/unit/initiative-copy.test.mjs).

export const HERO_SUB =
  'Named goals that group related jobs, so you can see how far a piece of work has got.';

export const EMPTY_TITLE = 'No initiatives yet';

export const EMPTY_BODY =
  'An initiative is a named goal, such as "Close the Q4 patch backlog". Create one with New Initiative. ' +
  'Then either attach existing jobs to it, or pick it in the Initiative field when you create a Scheduled Assessment, ' +
  'so every job that schedule produces is added to it automatically.';

export const DRAWER_EMPTY =
  'No jobs yet. Use Attach Job to add jobs that have no initiative, or link a Scheduled Assessment to this initiative.';
