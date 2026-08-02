// Comment board — renders user comments safely.
// NOTE: using textContent (not innerHTML) for comment text. Setting innerHTML
// with untrusted comment text enables stored XSS; textContent treats the input
// as plain text, so any <script>/markup in a comment is shown literally.

const form = document.getElementById('comment-form');
const input = document.getElementById('comment-input');
const list = document.getElementById('comment-list');

function escapeHtml(str) {
  // Defense-in-depth: escape for any context where innerHTML might be used.
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderComment(text) {
  const item = document.createElement('li');
  item.className = 'comment';

  const body = document.createElement('span');
  body.className = 'comment__body';
  body.textContent = text; // safe: no parsing of markup

  const time = document.createElement('time');
  time.className = 'comment__time';
  time.textContent = new Date().toLocaleString();

  item.appendChild(body);
  item.appendChild(time);
  return item;
}

function addComment(text) {
  const trimmed = (text || '').trim();
  if (!trimmed) return;
  list.appendChild(renderComment(trimmed));
}

form.addEventListener('submit', (e) => {
  e.preventDefault();
  addComment(input.value);
  input.value = '';
  input.focus();
});
