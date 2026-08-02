const form = document.getElementById('comment-form');
const input = document.getElementById('comment-input');
const list = document.getElementById('comments');

// ponytail: escape before innerHTML — raw user text in innerHTML is stored XSS
const esc = (s) =>
  s.replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const text = input.value.trim();
  if (!text) return;
  const item = document.createElement('li');
  item.innerHTML = esc(text);
  list.appendChild(item);
  input.value = '';
});
