(function () {
  const form = document.getElementById('comment-form');
  const input = document.getElementById('comment-input');
  const list = document.getElementById('comment-list');

  const comments = [];

  function escapeHtml(str) {
    // Defense-in-depth: sanitize before insertion even though we use
    // textContent below. If this string is ever routed through innerHTML
    // elsewhere, the markup is neutralized.
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function render() {
    // Rebuild the list. Each comment's text is assigned via textContent,
    // which treats it as plain text and never parses it as HTML/JS.
    list.replaceChildren();

    for (const comment of comments) {
      const article = document.createElement('article');
      article.className = 'comment';

      const body = document.createElement('p');
      body.className = 'comment-body';
      body.textContent = comment.text; // safe: no HTML parsing

      const meta = document.createElement('time');
      meta.className = 'comment-time';
      meta.dateTime = comment.createdAt;
      meta.textContent = new Date(comment.createdAt).toLocaleString();

      article.append(body, meta);
      list.append(article);
    }
  }

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const text = input.value.trim();
    if (!text) return;

    comments.push({ text, createdAt: new Date().toISOString() });
    input.value = '';
    render();
  });

  render();
})();
