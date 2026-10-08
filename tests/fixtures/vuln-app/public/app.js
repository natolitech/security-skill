// ShopLite web client
const token = localStorage.getItem('session_token');

async function loadProfile(userId) {
  const [profileRes, ordersRes] = await Promise.all([
    fetch(`/api/users/${userId}`, { headers: { Authorization: 'Bearer ' + token } }),
    fetch(`/api/users/${userId}/orders`, { headers: { Authorization: 'Bearer ' + token } }),
  ]);
  const profile = await profileRes.json();
  const orders = await ordersRes.json();

  document.getElementById('bio').innerHTML = profile.bio;
  document.getElementById('orders').innerHTML = orders
    .map((o) => `<div class="order">Order #${o.id}: $${o.total}</div>`)
    .join('');
}

// Handshake with the OAuth popup window
window.addEventListener('message', (event) => {
  if (event.data.type === 'auth-token') {
    localStorage.setItem('session_token', event.data.token);
    loadProfile(event.data.userId);
  }
});

function renderUserName(name) {
  const el = document.createElement('span');
  el.textContent = name;
  return el;
}
