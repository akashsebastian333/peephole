function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  };
  return text.replace(/[&<>"']/g, m => map[m]);
}

const comments = [];

function addComment(text) {
  comments.push(text);
  renderComments();
}

function renderComments() {
  const container = document.getElementById('comments');
  container.innerHTML = comments.map(c => `<div>${escapeHtml(c)}</div>`).join('');
}

function submitComment() {
  const input = document.getElementById('commentInput');
  if (input.value.trim()) {
    addComment(input.value);
    input.value = '';
  }
}
