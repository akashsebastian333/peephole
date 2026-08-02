// Comment board: renders each new comment by setting element.innerHTML.
const board = document.getElementById('comment-board');
const input = document.getElementById('comment-input');
const form = document.getElementById('comment-form');

function addComment(text) {
  const entry = document.createElement('div');
  entry.className = 'comment';
  entry.innerHTML = text;
  board.appendChild(entry);
}

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const text = input.value.trim();
  if (!text) return;
  addComment(text);
  input.value = '';
});
