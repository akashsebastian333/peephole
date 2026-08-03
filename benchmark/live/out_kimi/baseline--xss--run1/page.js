const form = document.getElementById('comment-form');
const input = document.getElementById('comment-input');
const list = document.getElementById('comments');

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const text = input.value;
  if (!text) return;

  const el = document.createElement('div');
  el.className = 'comment';
  el.innerHTML = text;
  list.appendChild(el);

  input.value = '';
});
