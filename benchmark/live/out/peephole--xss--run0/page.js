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

  renderComments(comments) {
    this.container.innerHTML = '';
    comments.forEach(comment => {
      this.addComment(comment);
    });
  }
}

export default CommentBoard;
