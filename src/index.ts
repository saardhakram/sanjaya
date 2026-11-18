// Vercel entrypoint: Vercel's Express support looks for a file that imports
// express and default-exports an app. The real app (routes, security, API)
// is built in src/server and mounted here; static assets come from public/.
import express from 'express';
import { buildApp } from './server/bootstrap.js';

const app = express();
app.disable('x-powered-by');
app.use(buildApp().app);

export default app;
