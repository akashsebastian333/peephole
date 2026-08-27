// Comment board: renders each new comment into the list.
// Uses textContent so comment text is treated as plain text, never as
// HTML/script — preventing XSS from user-supplied content.

function renderComment(board, comment) {
  const item = document.createElement('li');
  item.className = 'comment';
  item.textContent = comment.text;
  board.appendChild(item);
}

function addComment(board, text) {
  if (!text || !text.trim()) return;
  renderComment(board, { text });
}

document.addEventListener('DOMContentLoaded', () => {
  const board = document.getElementById('comment-board');
  const form = document.getElementById('comment-form');
  const input = document.getElementById('comment-input');

  if (form && input && board) {
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      addComment(board, input.value);
      input.value = '';
      input.focus();
    });
  }
});
