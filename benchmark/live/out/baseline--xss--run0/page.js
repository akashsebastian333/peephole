const commentContainer = document.getElementById('comments');

function addComment(commentText) {
  const commentElement = document.createElement('div');
  commentElement.className = 'comment';
  commentElement.innerHTML = commentText;
  commentContainer.appendChild(commentElement);
}

function loadComments(comments) {
  comments.forEach(comment => {
    addComment(comment);
  });
}
