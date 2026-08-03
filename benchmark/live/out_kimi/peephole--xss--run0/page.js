const form = document.getElementById('comment-form');
const input = document.getElementById('comment-input');
const list = document.getElementById('comments');

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const text = input.value.trim();
  if (!text) return;

  const li = document.createElement('li');
  // ponytail: textContent, not innerHTML — comment text is untrusted; innerHTML here is stored XSS
  li.textContent = text;
  list.appendChild(li);

  input.value = '';
});
