function addComment(text) {
  const container = document.getElementById('comments');
  const comment = document.createElement('div');
  comment.textContent = text;
  container.appendChild(comment);
}
