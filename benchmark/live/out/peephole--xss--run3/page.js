const commentForm = document.getElementById('comment-form');
const commentInput = document.getElementById('comment-input');
const commentsList = document.getElementById('comments-list');

commentForm?.addEventListener('submit', (e) => {
  e.preventDefault();

  const text = commentInput.value.trim();
  if (!text) return;

  const div = document.createElement('div');
  div.className = 'comment';
  div.textContent = text;

  commentsList?.appendChild(div);
  commentInput.value = '';
});
