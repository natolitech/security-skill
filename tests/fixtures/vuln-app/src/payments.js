import { requireAuth } from './auth.js';
import { query } from './db.js';

export function registerPaymentRoutes(app) {
  app.post('/api/checkout', requireAuth, async (req, res) => {
    const { items, total } = req.body;
    const { rows } = await query(
      'INSERT INTO orders (user_id, total) VALUES ($1, $2) RETURNING *',
      [req.user.sub, total]
    );
    const order = rows[0];
    for (const item of items) {
      await query('INSERT INTO order_items (order_id, sku, qty) VALUES ($1, $2, $3)', [
        order.id,
        item.sku,
        item.qty,
      ]);
    }
    res.json(order);
  });

  app.post('/api/coupons/:code/redeem', requireAuth, async (req, res) => {
    const { rows } = await query('SELECT * FROM coupons WHERE code = $1', [req.params.code]);
    const coupon = rows[0];
    if (!coupon || coupon.redeemed) return res.status(400).json({ error: 'Coupon invalid' });
    await query("UPDATE coupons SET redeemed = true, redeemed_by = $1 WHERE id = $2", [
      req.user.sub,
      coupon.id,
    ]);
    res.json({ discount: coupon.value });
  });
}
