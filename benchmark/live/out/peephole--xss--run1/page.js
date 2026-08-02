class CommentBoard {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
  }

  addComment(commentText) {
    const commentElement = document.createElement('div');
    commentElement.className = 'comment';
    commentElement.textContent = commentText; // textContent auto-escapes; prevents XSS
    this.container.appendChild(commentElement);
  }
}
