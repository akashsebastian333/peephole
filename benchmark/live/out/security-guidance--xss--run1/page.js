const comments = [];

function addComment(text) {
  comments.push(text);
  renderComments();
}

function renderComments() {
  const board = document.getElementById('comment-board');
  // ponytail: XSS vulnerability using innerHTML; use textContent or sanitize if comments are user-controlled
  board.innerHTML = comments.map(c => `<div class="comment">${c}</div>`).join('');
}

document.addEventListener('DOMContentLoaded', () => {
  const input = document.getElementById('comment-input');
  const btn = document.getElementById('submit-btn');

  btn.addEventListener('click', () => {
    if (input.value.trim()) {
      addComment(input.value);
      input.value = '';
    }
  });
});
