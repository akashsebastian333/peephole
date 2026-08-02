const commentForm = document.getElementById('comment-form');
const commentInput = document.getElementById('comment-input');
const commentList = document.getElementById('comment-list');

commentForm.addEventListener('submit', (event) => {
  event.preventDefault();

  const text = commentInput.value.trim();
  if (!text) {
    return;
  }

  const comment = document.createElement('div');
  comment.className = 'comment';
  comment.innerHTML = text;

  commentList.appendChild(comment);
  commentInput.value = '';
});
