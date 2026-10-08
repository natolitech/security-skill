import pg from 'pg';

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

// Standard query helper
export function query(text, params) {
  return pool.query(text, params);
}

// Storefront search
export async function searchProducts(term) {
  return query('SELECT id, name, price FROM products WHERE name ILIKE $1', [`%${term}%`]);
}
