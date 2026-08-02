function addComment(containerId, commentText) {
  const container = document.getElementById(containerId);
  const div = document.createElement('div');
  div.innerHTML = commentText;
  container.appendChild(div);
}
