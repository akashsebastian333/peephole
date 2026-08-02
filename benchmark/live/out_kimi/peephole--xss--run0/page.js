// Comment board: renders each new comment into #comments.
// Uses textContent so comment text can never inject markup (XSS-safe).

function renderComment(text) {
  const el = document.createElement('div');
  el.className = 'comment';
  el.textContent = text;
  document.getElementById('comments').appendChild(el);
}

document.getElementById('comment-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const input = document.getElementById('comment-input');
  const text = input.value.trim();
  if (!text) return;
  renderComment(text);
  input.value = '';
});
