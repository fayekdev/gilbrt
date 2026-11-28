import { copyFile } from 'node:fs/promises';
await copyFile(new URL('../../gilbrt/gui_assets/style.css', import.meta.url), new URL('../public/gui-demo.css', import.meta.url));
console.log('Synced actual gilbrt GUI stylesheet');
