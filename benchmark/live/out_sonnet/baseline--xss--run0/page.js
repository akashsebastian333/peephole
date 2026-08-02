const form = document.getElementById('comment-form');
const input = document.getElementById('comment-input');
const list = document.getElementById('comment-list');

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const text = input.value.trim();
  if (!text) return;

  const item = document.createElement('li');
  item.textContent = text; // ponytail: textContent, not innerHTML — avoids stored XSS from comment text
  list.appendChild(item);

  input.value = '';
});
