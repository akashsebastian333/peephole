document.addEventListener('DOMContentLoaded', function() {
  const commentContainer = document.getElementById('comments');

  function addComment(commentText) {
    const commentDiv = document.createElement('div');
    commentDiv.className = 'comment';
    commentDiv.innerHTML = commentText;
    commentContainer.appendChild(commentDiv);
  }

  window.addComment = addComment;
});
