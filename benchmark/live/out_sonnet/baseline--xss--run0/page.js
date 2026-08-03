const form = document.getElementById('comment-form');
const input = document.getElementById('comment-input');
const list = document.getElementById('comment-list');

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const text = input.value.trim();
  if (!text) return;

  const li = document.createElement('li');
  li.innerHTML = escapeHtml(text);
  list.appendChild(li);

  input.value = '';
});
