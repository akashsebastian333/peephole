const form = document.getElementById('comment-form');
const input = document.getElementById('comment-input');
const list = document.getElementById('comment-list');

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const text = input.value.trim();
  if (!text) return;

  const item = document.createElement('li');
  // ponytail: textContent instead of innerHTML — avoids XSS, CLAUDE.md requires output encoding at the sink
  item.textContent = text;
  list.appendChild(item);

  input.value = '';
});
