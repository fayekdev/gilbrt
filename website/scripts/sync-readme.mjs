import { copyFile } from 'node:fs/promises';
await copyFile(new URL('../../README.md', import.meta.url), new URL('../public/readme.md', import.meta.url));
console.log('Synced repository README to public/readme.md');
