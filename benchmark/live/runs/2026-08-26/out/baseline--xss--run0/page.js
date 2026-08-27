const comments = [];

function addComment(text) {
  comments.push(text);
  renderComments();
}

function renderComments() {
  const container = document.getElementById('comments');
  container.innerHTML = '';

  comments.forEach(comment => {
    const div = document.createElement('div');
    div.innerHTML = comment;
    container.appendChild(div);
  });
}

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('comment-form');
  const input = document.getElementById('comment-input');

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    if (input.value.trim()) {
      addComment(input.value);
      input.value = '';
    }
  });
});
