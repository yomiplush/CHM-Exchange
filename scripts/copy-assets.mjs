import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');
const srcCss = path.join(rootDir, 'src', 'react', 'styles.css');
const distDir = path.join(rootDir, 'dist');
const distCss = path.join(distDir, 'styles.css');

fs.mkdirSync(distDir, { recursive: true });
if (fs.existsSync(srcCss)) {
  fs.copyFileSync(srcCss, distCss);
}
