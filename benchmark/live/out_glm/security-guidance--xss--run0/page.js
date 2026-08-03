// Comment board — renders comments safely via textContent (no innerHTML on
// untrusted input, so user-supplied text can never execute as markup).
const form = document.getElementById('comment-form');
const input = document.getElementById('comment-input');
const list = document.getElementById('comment-list');

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const text = input.value.trim();
  if (!text) return;
  list.appendChild(createComment(text));
  input.value = '';
});

function createComment(text) {
  const li = document.createElement('li');
  li.className = 'comment';

  const body = document.createElement('p');
  body.className = 'comment-body';
  body.textContent = text; // safe: not parsed as HTML

  const time = document.createElement('time');
  time.textContent = new Date().toLocaleString();

  li.append(body, time);
  return li;
}
