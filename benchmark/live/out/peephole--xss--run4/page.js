const comments = [];

function addComment(text) {
  const commentDiv = document.createElement('div');
  commentDiv.className = 'comment';
  commentDiv.textContent = text;
  document.getElementById('comments').appendChild(commentDiv);
  comments.push(text);
}

function renderComments() {
  const container = document.getElementById('comments');
  container.innerHTML = '';
  comments.forEach(text => {
    const commentDiv = document.createElement('div');
    commentDiv.className = 'comment';
    commentDiv.textContent = text;
    container.appendChild(commentDiv);
  });
}
