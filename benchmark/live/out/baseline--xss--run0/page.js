const comments = [];
const commentsList = document.getElementById('comments-list');

function addComment(text) {
  comments.push(text);
  renderComments();
}

function renderComments() {
  commentsList.innerHTML = '';
  comments.forEach(comment => {
    const div = document.createElement('div');
    div.className = 'comment';
    div.textContent = comment;
    commentsList.appendChild(div);
  });
}

// Initialize with any existing comments
renderComments();
