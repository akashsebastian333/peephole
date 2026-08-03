const form = document.getElementById('comment-form');
const input = document.getElementById('comment-input');
const list = document.getElementById('comments');

// Encode for the HTML sink before it touches innerHTML (stored-XSS guard).
function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[c]));
}

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const text = input.value.trim();
  if (!text) return;

  const el = document.createElement('div');
  el.className = 'comment';
  el.innerHTML = escapeHtml(text);
  list.appendChild(el);

  input.value = '';
});
