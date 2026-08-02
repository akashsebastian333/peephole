// Comment board: appends each submitted comment to the list.
// The untrusted comment text is placed via textContent, so it is
// always rendered as text and can never be parsed as markup.

const form = document.getElementById('comment-form');
const input = document.getElementById('comment-input');
const list = document.getElementById('comment-list');

function renderComment(text) {
  const item = document.createElement('li');
  item.className = 'comment';

  const body = document.createElement('div');
  body.className = 'comment-body';
  body.textContent = text; // safe: never parsed as HTML

  item.appendChild(body);
  return item;
}

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const text = input.value.trim();
  if (!text) return;
  list.appendChild(renderComment(text));
  input.value = '';
});
