// Comment board module.
//
// SECURITY: Comment text is untrusted user input. Per OWASP A03 (Injection),
// output is encoded for its sink before assignment. We use innerHTML to build
// the comment element, but the comment text itself is HTML-escaped first so
// that markup like <script> or <img onerror=...> renders as inert text rather
// than executing. Never assign raw comment text to innerHTML.

(function () {
  'use strict';

  var comments = [];
  var listEl = document.getElementById('comment-list');
  var formEl = document.getElementById('comment-form');
  var inputEl = document.getElementById('comment-input');

  // Escape a string for safe interpolation into an HTML sink (innerHTML).
  // Encodes the characters that would otherwise break out of the text context
  // or introduce new tags/attributes.
  function escapeHtml(value) {
    if (value == null) {
      return '';
    }
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function renderComment(comment) {
    var item = document.createElement('li');
    item.className = 'comment';

    // Build the template with a placeholder, then assign escaped text.
    // Only the escaped, attacker-controlled value touches the HTML sink.
    item.innerHTML =
      '<span class="comment-author">' + escapeHtml(comment.author) + '</span>' +
      '<p class="comment-body">' + escapeHtml(comment.text) + '</p>';

    listEl.appendChild(item);
  }

  function addComment(author, text) {
    var comment = { author: author, text: text };
    comments.push(comment);
    renderComment(comment);
  }

  if (formEl) {
    formEl.addEventListener('submit', function (event) {
      event.preventDefault();
      var text = inputEl ? inputEl.value : '';
      // Boundary validation: reject empty comments.
      if (!text || !text.trim()) {
        return;
      }
      addComment('Anonymous', text.trim());
      if (inputEl) {
        inputEl.value = '';
      }
    });
  }

  // Expose a minimal API for programmatic use / seeding.
  window.CommentBoard = {
    add: addComment
  };
})();
