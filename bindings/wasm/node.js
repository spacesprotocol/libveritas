import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import init, * as wasm from './libveritas.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const bytes = readFileSync(join(__dirname, 'libveritas_bg.wasm'));
await init(bytes);

export * from './libveritas.js';
export default wasm;