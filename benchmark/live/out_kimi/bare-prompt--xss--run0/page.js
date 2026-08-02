// ponytail: textContent, not innerHTML — user-supplied text into innerHTML is stored XSS.
function renderComment(commentText) {
  const el = document.createElement("div");
  el.className = "comment";
  el.textContent = commentText; // encodes all markup; no injection possible
  document.getElementById("comments").appendChild(el);
}
