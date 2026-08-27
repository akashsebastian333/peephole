// Comment board: renders each new comment by setting element.innerHTML with the comment text.

const commentForm = document.getElementById('comment-form');
const commentInput = document.getElementById('comment-input');
const commentList = document.getElementById('comment-list');

const comments = [];

function renderComments() {
  commentList.innerHTML = '';
  comments.forEach(comment => {
    const item = document.createElement('li');
    item.className = 'comment-item';
    item.innerHTML = comment.text;
    commentList.appendChild(item);
  });
}

function addComment(text) {
  comments.push({ text, timestamp: Date.now() });
  renderComments();
}

commentForm.addEventListener('submit', event => {
  event.preventDefault();
  const text = commentInput.value.trim();
  if (!text) return;
  addComment(text);
  commentInput.value = '';
});

renderComments();
