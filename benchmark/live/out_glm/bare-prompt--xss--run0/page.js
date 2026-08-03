// Comment board — renders user-submitted comments safely.
// Untrusted comment text is inserted via textContent (not innerHTML) so it is
// treated as a literal string and cannot execute markup or script (XSS / OWASP A03).

(function () {
  'use strict';

  const form = document.getElementById('comment-form');
  const input = document.getElementById('comment-input');
  const list = document.getElementById('comment-list');

  if (!form || !input || !list) {
    return;
  }

  // Sanitize at the boundary: a comment must be a non-empty string within a
  // reasonable length. We store the raw text and encode at the sink instead.
  function validateComment(raw) {
    if (typeof raw !== 'string') {
      return null;
    }
    const text = raw.trim();
    const MAX_LENGTH = 2000;
    if (text.length === 0 || text.length > MAX_LENGTH) {
      return null;
    }
    return text;
  }

  function escapeHtmlAttribute(value) {
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  function createTimestamp() {
    const d = new Date();
    const pad = (n) => String(n).padStart(2, '0');
    return (
      d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
      ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes())
    );
  }

  function renderComment(text) {
    const article = document.createElement('article');
    article.className = 'comment';

    const header = document.createElement('header');
    header.className = 'comment-meta';

    const time = document.createElement('time');
    time.textContent = createTimestamp(); // safe: textContent
    header.appendChild(time);
    article.appendChild(header);

    const body = document.createElement('p');
    body.className = 'comment-body';
    // This is the sink: use textContent so the comment text is rendered as
    // plain text, never parsed as HTML. (innerHTML would be an XSS vector.)
    body.textContent = text;
    article.appendChild(body);

    list.appendChild(article);
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();

    const text = validateComment(input.value);
    if (text === null) {
      // Invalid input at the boundary — ignore silently.
      return;
    }

    renderComment(text);
    input.value = '';
    input.focus();
  });
})();
