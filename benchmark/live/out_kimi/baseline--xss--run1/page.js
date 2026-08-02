function addComment(text) {
  const el = document.createElement('div');
  el.className = 'comment';
  el.innerHTML = text;
  document.getElementById('comments').appendChild(el);
}

document.getElementById('comment-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const input = document.getElementById('comment-input');
  addComment(input.value);
  input.value = '';
});
