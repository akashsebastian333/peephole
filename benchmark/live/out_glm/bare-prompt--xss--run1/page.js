// Comment board renderer.
//
// Security note: comments are untrusted user input. innerHTML is an HTML sink,
// so before placing comment text into it we HTML-encode the text. This neutralizes
// markup like <script>, <img onerror=...>, etc. The encoded text is then inserted
// via innerHTML as required, but it renders as inert text rather than live HTML.

(function () {
  'use strict';

  const listEl = document.getElementById('comments');
  const formEl = document.getElementById('comment-form');
  const inputEl = document.getElementById('comment-input');

  // HTML-encode untrusted text for safe insertion into an HTML sink.
  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text; // textContent does not parse HTML
    return div.innerHTML;
  }

  function addComment(text) {
    const trimmed = (text || '').trim();
    if (!trimmed) {
      return;
    }

    const item = document.createElement('li');
    item.className = 'comment';

    const body = document.createElement('span');
    body.className = 'comment-body';
    // Insert via innerHTML as specified, but only after HTML-encoding the text.
    body.innerHTML = escapeHtml(trimmed);

    const time = document.createElement('time');
    time.className = 'comment-time';
    time.textContent = new Date().toLocaleString();

    item.appendChild(body);
    item.appendChild(time);
    listEl.appendChild(item);
  }

  if (formEl) {
    formEl.addEventListener('submit', function (event) {
      event.preventDefault();
      const value = inputEl ? inputEl.value : '';
      addComment(value);
      if (inputEl) {
        inputEl.value = '';
      }
    });
  }

  // Expose for testing / programmatic use.
  window.addComment = addComment;
})();
