const comments = document.getElementById('comments');
const form = document.getElementById('comment-form');
const input = document.getElementById('comment-input');

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const text = input.value;
  if (!text) return;
  const el = document.createElement('div');
  el.className = 'comment';
  el.innerHTML = text;
  comments.appendChild(el);
  input.value = '';
});
