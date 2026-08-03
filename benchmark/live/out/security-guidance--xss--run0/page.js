class CommentBoard {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
  }

  addComment(commentText) {
    const commentElement = document.createElement('div');
    commentElement.className = 'comment';
    commentElement.textContent = commentText;
    this.container.appendChild(commentElement);
  }
}

const board = new CommentBoard('comments-container');
