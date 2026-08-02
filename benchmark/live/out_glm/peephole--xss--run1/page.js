(function () {
  const form = document.getElementById('comment-form');
  const input = document.getElementById('comment-input');
  const list = document.getElementById('comment-list');

  function addComment(text) {
    const item = document.createElement('li');
    item.className = 'comment-item';

    const body = document.createElement('div');
    body.className = 'comment-body';
    body.textContent = text;

    item.appendChild(body);
    list.appendChild(item);
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    const text = input.value.trim();
    if (!text) return;
    addComment(text);
    input.value = '';
    input.focus();
  });
})();
