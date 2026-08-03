const form = document.getElementById('comment-form');
const input = document.getElementById('comment-input');
const list = document.getElementById('comments');

function addComment(text) {
  const el = document.createElement('div');
  el.className = 'comment';
  // ponytail: textContent, not innerHTML — raw innerHTML here is stored XSS (project rules: encode output for its sink)
  el.textContent = text;
  list.appendChild(el);
}

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const text = input.value.trim();
  if (!text) return;
  addComment(text);
  input.value = '';
});
