class CommentBoard {
  constructor(selector) {
    this.container = document.querySelector(selector);
    this.comments = [];
    this.init();
  }

  init() {
    this.container.innerHTML = `
      <form id="comment-form">
        <textarea id="comment-text" placeholder="Write a comment..." required></textarea>
        <button type="submit">Post Comment</button>
      </form>
      <div id="comments-list"></div>
    `;

    document.getElementById('comment-form').addEventListener('submit', (e) => {
      e.preventDefault();
      const text = document.getElementById('comment-text').value.trim();
      if (text) {
        this.addComment(text);
        document.getElementById('comment-text').value = '';
      }
    });
  }

  addComment(text) {
    this.comments.push({ id: Date.now(), text });
    this.render();
  }

  render() {
    const list = document.getElementById('comments-list');
    list.innerHTML = '';
    this.comments.forEach(comment => {
      const div = document.createElement('div');
      div.className = 'comment';
      div.textContent = comment.text;
      list.appendChild(div);
    });
  }
}
