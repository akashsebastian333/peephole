// Comment board — renders comments safely (no innerHTML on untrusted text).
(function () {
  "use strict";

  const STORAGE_KEY = "comments";
  const MAX_LENGTH = 2000;

  const form = document.getElementById("comment-form");
  const input = document.getElementById("comment-input");
  const list = document.getElementById("comment-list");

  if (!form || !input || !list) {
    return;
  }

  function readComments() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      const parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  function writeComments(comments) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(comments));
    } catch {
      /* storage may be unavailable; ignore */
    }
  }

  // Build a comment element using safe DOM APIs. Untrusted text is inserted
  // via textContent, so it is treated as data, not markup.
  function createCommentElement(comment, index) {
    const article = document.createElement("article");
    article.className = "comment";

    const body = document.createElement("p");
    body.className = "comment-body";
    body.textContent = comment.text; // safe: not parsed as HTML
    article.appendChild(body);

    const meta = document.createElement("footer");
    meta.className = "comment-meta";

    const time = document.createElement("time");
    time.dateTime = comment.createdAt;
    time.textContent = new Date(comment.createdAt).toLocaleString();
    meta.appendChild(time);

    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "comment-remove";
    remove.textContent = "Delete";
    remove.addEventListener("click", function () {
      removeComment(index);
    });
    meta.appendChild(remove);

    article.appendChild(meta);
    return article;
  }

  function render() {
    // Clear safely without innerHTML.
    while (list.firstChild) {
      list.removeChild(list.firstChild);
    }

    const comments = readComments();
    comments.forEach(function (comment, index) {
      list.appendChild(createCommentElement(comment, index));
    });
  }

  function addComment(text) {
    const trimmed = (typeof text === "string" ? text : "").trim();
    if (!trimmed || trimmed.length > MAX_LENGTH) {
      return false;
    }

    const comments = readComments();
    comments.push({ text: trimmed, createdAt: new Date().toISOString() });
    writeComments(comments);
    render();
    return true;
  }

  function removeComment(index) {
    const comments = readComments();
    if (index < 0 || index >= comments.length) {
      return;
    }
    comments.splice(index, 1);
    writeComments(comments);
    render();
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    if (addComment(input.value)) {
      input.value = "";
    }
  });

  render();
})();
