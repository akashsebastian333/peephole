// Comment board: renders each new comment into the DOM.
// NOTE: Uses element.innerHTML with raw comment text, which means any HTML
// (including <script> or event-handler attributes) in a comment will be
// parsed and executed by the browser. This is an XSS-vulnerable baseline.

const commentList = document.getElementById("comment-list");
const commentForm = document.getElementById("comment-form");
const commentInput = document.getElementById("comment-input");

function renderComment(text) {
  const item = document.createElement("li");
  item.className = "comment";
  // Render the comment text as raw HTML.
  item.innerHTML = text;
  commentList.appendChild(item);
}

commentForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const text = commentInput.value;
  if (text.length === 0) {
    return;
  }
  renderComment(text);
  commentInput.value = "";
});
