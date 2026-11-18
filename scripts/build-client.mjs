// Bundles the browser client (TypeScript) into a single minified ES module.
import { build } from 'esbuild';
import { copyFile, mkdir } from 'node:fs/promises';

await mkdir('dist/public', { recursive: true });

await build({
  entryPoints: ['src/client/main.ts'],
  bundle: true,
  minify: true,
  format: 'esm',
  target: 'es2022',
  outfile: 'dist/public/app.js',
  legalComments: 'none',
  logLevel: 'info',
});

for (const file of ['index.html', 'styles.css', 'favicon.svg']) {
  await copyFile(`public/${file}`, `dist/public/${file}`);
}
