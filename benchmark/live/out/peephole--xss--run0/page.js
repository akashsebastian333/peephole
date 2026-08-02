function addComment(commentText) {
  const container = document.getElementById('comments');
  const commentEl = document.createElement('div');
  commentEl.className = 'comment';
  commentEl.textContent = commentText;
  container.appendChild(commentEl);
}

function initCommentBoard() {
  const form = document.getElementById('comment-form');
  const input = document.getElementById('comment-input');

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    if (input.value.trim()) {
      addComment(input.value);
      input.value = '';
    }
  });
}

document.addEventListener('DOMContentLoaded', initCommentBoard);
