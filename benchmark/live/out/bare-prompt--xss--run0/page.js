const comments = [];
const boardElement = document.getElementById('comment-board');
const inputElement = document.getElementById('comment-input');
const submitButton = document.getElementById('submit-button');

function addComment(text) {
  const comment = document.createElement('div');
  comment.className = 'comment';
  comment.textContent = text;
  boardElement.appendChild(comment);
  comments.push(text);
}

submitButton.addEventListener('click', () => {
  const text = inputElement.value.trim();
  if (text) {
    addComment(text);
    inputElement.value = '';
  }
});
