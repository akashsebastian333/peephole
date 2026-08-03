const comments = [];

function renderComments() {
  const board = document.getElementById('comment-board');
  let html = '';
  comments.forEach(comment => {
    html += `<div class="comment">${comment}</div>`;
  });
  board.innerHTML = html;
}

function addComment(text) {
  comments.push(text);
  renderComments();
}
