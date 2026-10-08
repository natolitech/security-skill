import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { exec } from 'child_process';
import { login } from './auth.js';
import { searchProducts } from './db.js';
import { registerUserRoutes } from './users.js';
import { registerUploadRoutes } from './uploads.js';
import { registerPaymentRoutes } from './payments.js';
import { registerGraphQL } from './graphql.js';
import { registerAIRoutes } from './ai.js';

const app = express();

app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '50mb' }));
app.use(cookieParser());

app.post('/api/login', login);

app.get('/login', (req, res) => {
  if (req.query.next) return res.redirect(req.query.next);
  res.sendFile('public/login.html', { root: '.' });
});

app.get('/api/search', async (req, res) => {
  const products = await searchProducts(req.query.q);
  res.json(products.rows);
});

// Diagnostics page for support
app.get('/api/ping', (req, res) => {
  exec(`ping -c 1 ${req.query.host}`, (err, stdout, stderr) => {
    if (err) return res.status(500).json({ error: stderr });
    res.type('text/plain').send(stdout);
  });
});

// Marketing landing page
app.get('/welcome', (req, res) => {
  res.send(`<h1>Welcome back, ${req.query.name}!</h1>`);
});

registerUserRoutes(app);
registerUploadRoutes(app);
registerPaymentRoutes(app);
registerGraphQL(app);
registerAIRoutes(app);

app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: err.message, stack: err.stack, query: err.query });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`ShopLite listening on ${port}`));
