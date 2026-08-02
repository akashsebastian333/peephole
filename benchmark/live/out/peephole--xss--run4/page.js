class CommentBoard {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
  }

  addComment(text) {
    const comment = document.createElement('div');
    comment.className = 'comment';
    comment.textContent = text;
    this.container.appendChild(comment);
  }

  render(comments) {
    this.container.innerHTML = '';
    comments.forEach(text => this.addComment(text));
  }
}

const board = new CommentBoard('comments');
