(function () {
  "use strict";

  var board = document.getElementById("board");
  var input = document.getElementById("comment-input");
  var form = document.getElementById("comment-form");

  // Encode untrusted comment text for the innerHTML sink to prevent XSS.
  // Although the sink is innerHTML, the comment text is escaped first so it
  // is treated as text, not markup.
  function escapeHtml(text) {
    return String(text)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function addComment(text) {
    if (typeof text !== "string" || text.length === 0) {
      return;
    }
    var item = document.createElement("div");
    item.className = "comment";
    var safe = escapeHtml(text);
    item.innerHTML = safe;
    board.appendChild(item);
  }

  if (form) {
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      var value = input ? input.value : "";
      addComment(value);
      if (input) {
        input.value = "";
      }
    });
  }

  // Expose for embedding / programmatic use.
  window.CommentBoard = { addComment: addComment };
})();
