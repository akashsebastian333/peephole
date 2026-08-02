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
      .map(comment => `<div class="comment">${comment}</div>`)
      .join('');
  }
}
