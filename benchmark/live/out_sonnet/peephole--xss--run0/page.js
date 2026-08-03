const form = document.getElementById('comment-form');
const input = document.getElementById('comment-input');
const list = document.getElementById('comment-list');

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const text = input.value.trim();
  if (!text) return;

  const li = document.createElement('li');
  li.textContent = text; // ponytail: textContent auto-escapes, avoids stored XSS from innerHTML
  list.appendChild(li);

  input.value = '';
});
