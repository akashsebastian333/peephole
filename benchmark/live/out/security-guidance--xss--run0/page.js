const commentBoard = document.getElementById('comment-board');
const commentInput = document.getElementById('comment-input');
const submitBtn = document.getElementById('submit-btn');

submitBtn.addEventListener('click', () => {
  const text = commentInput.value.trim();
  if (text) {
    const commentEl = document.createElement('div');
    commentEl.textContent = text;
    commentBoard.appendChild(commentEl);
    commentInput.value = '';
  }
});
