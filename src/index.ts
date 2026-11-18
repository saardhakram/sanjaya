// Vercel entrypoint: Vercel's Express support imports this file and serves the
// default-exported app as a function. Static assets are served from public/.
import { buildApp } from './server/bootstrap.js';

export default buildApp().app;
