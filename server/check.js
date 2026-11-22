// npm run check: lists what still needs doing before the site goes public. Exit code 1 when
// something must be fixed, so it can also stop a deploy script.
import { preflight, printPreflight } from './preflight.js';

const items = preflight();
printPreflight(items);
process.exit(items.some((i) => i.level === 'error') ? 1 : 0);
