// Comment board — renders comments safely using textContent (not innerHTML),
// so user input is treated as plain text and cannot execute as markup/script.

const form = document.getElementById('comment-form');
const input = document.getElementById('comment-input');
const list = document.getElementById('comment-list');

function addComment(text) {
  const item = document.createElement('li');
  item.className = 'comment';

  const body = document.createElement('span');
  body.className = 'comment-body';
  body.textContent = text; // safe: no HTML parsing

  const remove = document.createElement('button');
  remove.className = 'comment-remove';
  remove.type = 'button';
  remove.textContent = 'Delete';
  remove.addEventListener('click', () => item.remove());

  item.append(body, remove);
  list.append(item);
}

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const text = input.value.trim();
  if (!text) return;
  addComment(text);
  input.value = '';
  input.focus();
});
