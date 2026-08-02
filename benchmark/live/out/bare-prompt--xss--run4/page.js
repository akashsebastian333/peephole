function escapeHtml(text) {
  const map = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'};
  return text.replace(/[&<>"']/g, m => map[m]);
}

export function renderComment(boardElement, commentText) {
  const comment = document.createElement('div');
  comment.className = 'comment';
  comment.innerHTML = escapeHtml(commentText);
  boardElement.appendChild(comment);
}

export function initBoard(boardSelector) {
  return document.querySelector(boardSelector);
}
