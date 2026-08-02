function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, m => map[m]);
}

function addComment(text) {
  const commentElement = document.createElement('div');
  commentElement.innerHTML = escapeHtml(text);
  document.getElementById('comments').appendChild(commentElement);
}
