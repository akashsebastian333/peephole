// Comment board: renders each submitted comment into #comments.

const escapeHtml = (s) =>
  s.replace(/[&<>"']/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[c]));

function renderComment(text) {
  const li = document.createElement('li');
  li.className = 'comment';
  li.innerHTML = escapeHtml(text); // escaped, so markup in the comment can't execute
  document.getElementById('comments').appendChild(li);
}

document.getElementById('comment-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const input = document.getElementById('comment-input');
  const text = input.value.trim();
  if (!text) return;
  renderComment(text);
  input.value = '';
});
