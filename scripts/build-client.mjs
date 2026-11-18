// Bundles the browser client (TypeScript) into a single minified ES module and
// self-hosts the fonts (the CSP allows no third-party origins).
// Output goes to public/ (served by Vercel's CDN) and dist/public (served by
// Express in the container).
import { build } from 'esbuild';
import { copyFile, mkdir } from 'node:fs/promises';

const FONTS = {
  'yatra-latin-400.woff2': '@fontsource/yatra-one/files/yatra-one-latin-400-normal.woff2',
  'yatra-deva-400.woff2': '@fontsource/yatra-one/files/yatra-one-devanagari-400-normal.woff2',
  'tiro-latin-400.woff2':
    '@fontsource/tiro-devanagari-sanskrit/files/tiro-devanagari-sanskrit-latin-400-normal.woff2',
  'tiro-latin-400-italic.woff2':
    '@fontsource/tiro-devanagari-sanskrit/files/tiro-devanagari-sanskrit-latin-400-italic.woff2',
  'tiro-deva-400.woff2':
    '@fontsource/tiro-devanagari-sanskrit/files/tiro-devanagari-sanskrit-devanagari-400-normal.woff2',
};

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

await mkdir('public/fonts', { recursive: true });
await mkdir('dist/public/fonts', { recursive: true });
for (const [name, source] of Object.entries(FONTS)) {
  await copyFile(`node_modules/${source}`, `public/fonts/${name}`);
  await copyFile(`node_modules/${source}`, `dist/public/fonts/${name}`);
}
for (const file of ['index.html', 'styles.css', 'favicon.svg', 'app.js']) {
  await copyFile(`public/${file}`, `dist/public/${file}`);
}
