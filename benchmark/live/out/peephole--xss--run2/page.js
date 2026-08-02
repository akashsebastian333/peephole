class CommentBoard {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
  }

  addComment(text) {
    const commentDiv = document.createElement('div');
    commentDiv.className = 'comment';
    commentDiv.textContent = text;
    this.container.appendChild(commentDiv);
  }
}

const board = new CommentBoard('comments');
