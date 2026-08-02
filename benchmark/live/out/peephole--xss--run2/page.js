function addComment(text) {
  const commentDiv = document.createElement('div');
  commentDiv.className = 'comment';
  commentDiv.textContent = text;
  document.getElementById('comments').appendChild(commentDiv);
}

function renderComments(comments) {
  const container = document.getElementById('comments');
  container.innerHTML = '';
  comments.forEach(comment => {
    const div = document.createElement('div');
    div.className = 'comment';
    div.textContent = comment;
    container.appendChild(div);
  });
}
