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
    let html = '';
    for (const comment of this.comments) {
      html += `<div class="comment">${comment}</div>`;
    }
    this.container.innerHTML = html;
  }
}

const board = new CommentBoard('comments');

document.getElementById('submit-btn')?.addEventListener('click', () => {
  const input = document.getElementById('comment-input');
  if (input.value.trim()) {
    board.addComment(input.value);
    input.value = '';
  }
});
