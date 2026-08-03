const list = document.getElementById('comments');
const form = document.getElementById('comment-form');
const input = document.getElementById('comment-input');

function renderComment(text) {
  const el = document.createElement('div');
  el.className = 'comment';
  el.innerHTML = text;
  list.appendChild(el);
}

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const text = input.value.trim();
  if (!text) return;
  renderComment(text);
  input.value = '';
});
