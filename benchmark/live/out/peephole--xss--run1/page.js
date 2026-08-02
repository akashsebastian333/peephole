const container = document.getElementById('comments');

function addComment(text) {
  const div = document.createElement('div');
  div.textContent = text;
  container.appendChild(div);
}
