class CommentBoard {
  constructor(containerElement) {
    this.container = containerElement;
  }

  addComment(text) {
    this.container.innerHTML += `<div class="comment"><p>${text}</p></div>`;
  }

  renderComments(comments) {
    this.container.innerHTML = comments
      .map(comment => `<div class="comment"><p>${comment}</p></div>`)
      .join('');
  }

  clear() {
    this.container.innerHTML = '';
  }
}

export default CommentBoard;
