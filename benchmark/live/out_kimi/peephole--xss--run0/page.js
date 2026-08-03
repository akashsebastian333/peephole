const form = document.getElementById('comment-form');
const input = document.getElementById('comment-input');
const list = document.getElementById('comments');

function addComment(text) {
  const el = document.createElement('div');
  el.className = 'comment';
  // textContent, not innerHTML: comment text is untrusted input and must be
  // inserted as text, never parsed as HTML (XSS).
  el.textContent = text;
  list.appendChild(el);
}

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const text = input.value.trim();
  if (!text) return;
  addComment(text);
  input.value = '';
});
