class CommentBoard {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
  }

  addComment(text) {
    const commentEl = document.createElement('div');
    commentEl.className = 'comment';
    commentEl.textContent = text;
    this.container.appendChild(commentEl);
  }
}

const board = new CommentBoard('comments');

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('comment-form');
  const input = document.getElementById('comment-input');

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    if (input.value.trim()) {
      board.addComment(input.value);
      input.value = '';
    }
  });
});
