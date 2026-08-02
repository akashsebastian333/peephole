// Encode before innerHTML — raw insertion would be stored XSS.
function escapeHtml(s) {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function addComment(text) {
  const el = document.createElement("div");
  el.className = "comment";
  el.innerHTML = escapeHtml(text);
  document.getElementById("comments").appendChild(el);
}

document.getElementById("comment-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const input = document.getElementById("comment-input");
  if (input.value.trim()) addComment(input.value);
  input.value = "";
});
