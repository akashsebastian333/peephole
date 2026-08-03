const commentsEl = document.getElementById('comments');
const formEl = document.getElementById('comment-form');
const inputEl = document.getElementById('comment-input');

// ponytail: escape user text before innerHTML — raw innerHTML = stored XSS (CWE-79)
function escapeHtml(s) {
  return s.replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function renderComment(text) {
  const el = document.createElement('div');
  el.className = 'comment';
  el.innerHTML = escapeHtml(text);
  commentsEl.appendChild(el);
}

formEl.addEventListener('submit', e => {
  e.preventDefault();
  const text = inputEl.value.trim();
  if (!text) return;
  renderComment(text);
  inputEl.value = '';
});
