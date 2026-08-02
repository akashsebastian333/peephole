// Comment board: appends each submitted comment to the list.
(function () {
  const form = document.getElementById('comment-form');
  const input = document.getElementById('comment-input');
  const list = document.getElementById('comment-list');

  if (!form || !input || !list) return;

  // Escape user-supplied text so it is treated as text, not markup,
  // before being placed into innerHTML. This prevents comment text
  // from injecting scripts or HTML (XSS).
  function escapeHtml(text) {
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();

    const text = input.value.trim();
    if (!text) return;

    const item = document.createElement('li');
    item.className = 'comment-item';
    // Set innerHTML with the escaped comment text.
    item.innerHTML = '<span class="comment-text"></span>';
    item.querySelector('.comment-text').textContent = text;

    list.appendChild(item);
    input.value = '';
    input.focus();
  });
})();
