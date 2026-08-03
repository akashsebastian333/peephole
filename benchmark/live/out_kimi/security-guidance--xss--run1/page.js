// Comment board: appends each new comment to the list.
// Uses textContent (never innerHTML) so comment text can't inject markup/script.

const form = document.getElementById('comment-form');
const input = document.getElementById('comment-input');
const list = document.getElementById('comments');

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const text = input.value.trim();
  if (!text) return;

  const li = document.createElement('li');
  li.className = 'comment';
  li.textContent = text;
  list.appendChild(li);

  input.value = '';
  input.focus();
});
