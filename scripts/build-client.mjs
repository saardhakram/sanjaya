// Bundles the browser client (TypeScript) into a single minified ES module.
// The bundle is written to public/ (served by Vercel's CDN) and the static
// assets are copied to dist/public (served by Express in the container).
import { build } from 'esbuild';
import { copyFile, mkdir } from 'node:fs/promises';

await build({
  entryPoints: ['src/client/main.ts'],
  bundle: true,
  minify: true,
  format: 'esm',
  target: 'es2022',
  outfile: 'public/app.js',
  legalComments: 'none',
  logLevel: 'info',
});

await mkdir('dist/public', { recursive: true });
for (const file of ['index.html', 'styles.css', 'favicon.svg', 'app.js']) {
  await copyFile(`public/${file}`, `dist/public/${file}`);
}
