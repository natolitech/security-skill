import { requireAuth, verifyToken } from './auth.js';
import { query } from './db.js';

export function registerUserRoutes(app) {
  app.get('/api/me/orders', requireAuth, async (req, res) => {
    const { rows } = await query('SELECT * FROM orders WHERE user_id = $1', [req.user.sub]);
    res.json(rows);
  });

  app.get('/api/users/:id/orders', requireAuth, async (req, res) => {
    const { rows } = await query('SELECT * FROM orders WHERE user_id = $1', [req.params.id]);
    res.json(rows);
  });

  app.get('/api/admin/users', async (req, res) => {
    const sort = req.query.sort || 'id';
    const { rows } = await query(`SELECT id, email, role FROM users ORDER BY ${sort}`);
    res.json(rows);
  });

  // Link preview used by the share dialog
  app.post('/api/preview', requireAuth, async (req, res) => {
    const r = await fetch(req.body.url);
    const html = await r.text();
    const title = html.match(/<title>(.*)<\/title>/)?.[1];
    res.json({ title });
  });

  // Profile updates via the web client, which authenticates with the session cookie
  app.post('/api/profile', async (req, res) => {
    const user = verifyToken(req.cookies.session);
    await query('UPDATE users SET display_name = $1, email = $2 WHERE id = $3', [
      req.body.display_name,
      req.body.email,
      user.sub,
    ]);
    res.json({ ok: true });
  });

  app.put('/api/me', requireAuth, async (req, res) => {
    const fields = Object.keys(req.body).map((k, i) => `${k} = $${i + 1}`).join(', ');
    const values = Object.values(req.body);
    const { rows } = await query(
      `UPDATE users SET ${fields} WHERE id = $${values.length + 1} RETURNING *`,
      [...values, req.user.sub]
    );
    res.json(rows[0]);
  });
}
