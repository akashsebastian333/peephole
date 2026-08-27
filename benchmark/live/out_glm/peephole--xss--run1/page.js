// Comment board: renders each new comment into the list using safe DOM APIs.
// User-controlled text is assigned via textContent (not innerHTML), so any
// markup in a comment is treated as plain text and cannot execute.
(function () {
  const form = document.getElementById('comment-form');
  const input = document.getElementById('comment-input');
  const list = document.getElementById('comment-list');

  if (!form || !input || !list) return;

  const comments = [];

  function renderComments() {
    list.textContent = '';
    comments.forEach(function (c) {
      const item = document.createElement('div');
      item.className = 'comment';

      const author = document.createElement('span');
      author.className = 'comment-author';
      author.textContent = c.author || 'Anonymous';

      const text = document.createElement('p');
      text.className = 'comment-text';
      text.textContent = c.text;

      const time = document.createElement('time');
      time.className = 'comment-time';
      time.textContent = new Date(c.timestamp).toLocaleString();

      item.appendChild(author);
      item.appendChild(text);
      item.appendChild(time);
      list.appendChild(item);
    });
  }

  function addComment(text, author) {
    comments.push({
      text: text,
      author: author || 'Anonymous',
      timestamp: Date.now(),
    });
    renderComments();
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    const text = input.value.trim();
    if (!text) return;
    addComment(text);
    input.value = '';
  });

  // Expose for programmatic use / seeding.
  window.CommentBoard = { addComment: addComment };
})();
