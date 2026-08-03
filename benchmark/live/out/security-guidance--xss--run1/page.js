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
    let html = '';
    this.comments.forEach(comment => {
      html += `<div class="comment">${comment}</div>`;
    });
    this.container.innerHTML = html;
  }
}
