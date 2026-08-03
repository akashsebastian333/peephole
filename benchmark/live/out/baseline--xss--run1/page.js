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
      .map((comment, i) => `<div class="comment" data-id="${i}">${comment}</div>`)
      .join('');
  }
}

const board = new CommentBoard('comment-board');
