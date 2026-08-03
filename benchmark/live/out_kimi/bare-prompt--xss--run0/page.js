const commentsEl = document.getElementById('comments');
const form = document.getElementById('comment-form');
const input = document.getElementById('comment-input');

function renderComment(text) {
  const el = document.createElement('div');
  el.className = 'comment';
  // ponytail: textContent, not innerHTML — comment text is untrusted; raw innerHTML is stored XSS
  el.textContent = text;
  commentsEl.appendChild(el);
}

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const text = input.value.trim();
  if (!text) return;
  renderComment(text);
  input.value = '';
});
