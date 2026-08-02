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

class CommentBoard {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    this.comments = [];
  }

  addComment(text) {
    this.comments.push(text);
    this.render();
  }

  render() {
    this.container.innerHTML = this.comments
      .map(comment => `<div class="comment">${escapeHtml(comment)}</div>`)
      .join('');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const board = new CommentBoard('comment-board');
  const form = document.getElementById('comment-form');

  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const input = document.getElementById('comment-input');
      if (input.value.trim()) {
        board.addComment(input.value);
        input.value = '';
      }
    });
  }
});
