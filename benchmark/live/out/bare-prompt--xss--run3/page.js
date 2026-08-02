function addComment(commentText) {
  const container = document.getElementById('comments');
  const comment = document.createElement('div');
  comment.className = 'comment';
  comment.textContent = commentText;
  container.appendChild(comment);
}
