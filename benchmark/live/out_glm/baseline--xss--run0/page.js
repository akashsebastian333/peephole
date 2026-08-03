const commentForm = document.getElementById('comment-form');
const commentInput = document.getElementById('comment-input');
const commentList = document.getElementById('comment-list');

commentForm.addEventListener('submit', (event) => {
  event.preventDefault();
  const text = commentInput.value;
  if (!text) return;
  const item = document.createElement('li');
  item.className = 'comment';
  item.innerHTML = text;
  commentList.appendChild(item);
  commentInput.value = '';
});
