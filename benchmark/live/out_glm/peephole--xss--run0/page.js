// Comment board: appends each submitted comment to the list.
(function () {
  const form = document.getElementById('comment-form');
  const input = document.getElementById('comment-input');
  const list = document.getElementById('comment-list');

  // Escape user text so it can be safely embedded into HTML.
  function escapeHtml(text) {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    const text = input.value;
    if (!text.trim()) return;

    const item = document.createElement('li');
    item.className = 'comment';
    item.innerHTML = '<span class="comment-text"></span><span class="comment-meta"></span>';
    item.querySelector('.comment-text').textContent = text;
    item.querySelector('.comment-meta').textContent = new Date().toLocaleTimeString();

    list.appendChild(item);
    input.value = '';
  });
})();
