// Comment board renderer.
// Comments are untrusted user input. We render them with textContent so the
// browser treats them as plain text, not HTML — preventing stored XSS.
// (Using element.innerHTML here would let a comment like
//  <img src=x onerror=alert(1)> execute as markup.)

(function () {
  const form = document.getElementById('comment-form');
  const input = document.getElementById('comment-input');
  const list = document.getElementById('comment-list');

  if (!form || !input || !list) {
    return;
  }

  function escapeForAttrib(value) {
    // For any attribute sink, encode quotes and the angle/amp trio.
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function renderComment(text) {
    const item = document.createElement('article');
    item.className = 'comment';

    const body = document.createElement('p');
    body.className = 'comment__body';
    body.textContent = text; // safe: not parsed as HTML

    const meta = document.createElement('time');
    meta.className = 'comment__time';
    meta.dateTime = new Date().toISOString();
    meta.textContent = new Date().toLocaleString();

    item.appendChild(body);
    item.appendChild(meta);
    return item;
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();

    const text = input.value.trim();
    if (!text) {
      return;
    }

    list.prepend(renderComment(text));
    input.value = '';
    input.focus();
  });

  // If existing comments are injected server-side via a data attribute,
  // read and render them safely too.
  const seed = list.getAttribute('data-seed-comments');
  if (seed) {
    try {
      const comments = JSON.parse(seed);
      if (Array.isArray(comments)) {
        comments.forEach(function (c) {
          if (typeof c === 'string') {
            list.appendChild(renderComment(c));
          }
        });
      }
    } catch (_e) {
      // Malformed seed data — ignore rather than render raw.
    }
  }
})();
