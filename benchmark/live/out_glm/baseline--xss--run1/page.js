// Comment board: renders each new comment into the list.
(function () {
  const form = document.getElementById('comment-form');
  const input = document.getElementById('comment-input');
  const list = document.getElementById('comment-list');

  function addComment(text) {
    const item = document.createElement('li');
    item.className = 'comment-item';
    item.innerHTML = text;
    list.appendChild(item);
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    const text = input.value.trim();
    if (!text) return;
    addComment(text);
    input.value = '';
  });
})();
