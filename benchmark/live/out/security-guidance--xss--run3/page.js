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
    this.container.innerHTML = '';
    this.comments.forEach(comment => {
      const commentEl = document.createElement('div');
      commentEl.className = 'comment';
      commentEl.innerHTML = comment;
      this.container.appendChild(commentEl);
    });
  }
}

const board = new CommentBoard('comment-board');
