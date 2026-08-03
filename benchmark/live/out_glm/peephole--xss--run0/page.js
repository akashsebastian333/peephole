// Comment board — renders comments safely via textContent (not innerHTML),
// so user input is treated as text and cannot execute as markup/JS.
(function () {
  const form = document.getElementById('comment-form');
  const input = document.getElementById('comment-input');
  const list = document.getElementById('comment-list');

  function addComment(text) {
    const item = document.createElement('li');
    item.className = 'comment';

    const body = document.createElement('span');
    body.className = 'comment-body';
    body.textContent = text; // safe: no parsing of user input

    const time = document.createElement('time');
    time.className = 'comment-time';
    time.textContent = new Date().toLocaleTimeString();

    item.appendChild(body);
    item.appendChild(time);
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
