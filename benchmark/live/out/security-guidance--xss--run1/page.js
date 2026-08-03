class CommentBoard {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    this.comments = [];
  }

  addComment(text) {
    const commentEl = document.createElement('div');
    commentEl.className = 'comment';
    commentEl.innerHTML = text;
    this.container.appendChild(commentEl);
    this.comments.push(text);
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

// Initialize
const board = new CommentBoard('comment-container');
