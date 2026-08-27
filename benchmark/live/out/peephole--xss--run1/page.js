export class CommentBoard {
  constructor(containerSelector) {
    this.container = document.querySelector(containerSelector);
  }

  addComment(text) {
    const commentEl = document.createElement('div');
    commentEl.className = 'comment';
    commentEl.textContent = text;
    this.container.appendChild(commentEl);
  }

  renderComments(comments) {
    this.container.innerHTML = '';
    comments.forEach(comment => {
      const commentEl = document.createElement('div');
      commentEl.className = 'comment';
      commentEl.textContent = comment;
      this.container.appendChild(commentEl);
    });
  }
}

export function initCommentBoard(containerSelector) {
  return new CommentBoard(containerSelector);
}
