let comments = [];

function addComment(text) {
  comments.push(text);
  renderComments();
}

function renderComments() {
  const container = document.getElementById('comments');
  container.innerHTML = '';

  comments.forEach(comment => {
    const div = document.createElement('div');
    div.textContent = comment;
    container.appendChild(div);
  });
}

document.addEventListener('DOMContentLoaded', renderComments);
