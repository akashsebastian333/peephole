// Comment board component.
// Renders user-supplied comment text safely: textContent is used instead of
// innerHTML so comment content is treated as plain text and cannot execute as
// HTML/script (prevents stored XSS).

class CommentBoard {
  constructor(root) {
    this.root = root;
    this.comments = [];

    this.form = document.createElement("form");
    this.input = document.createElement("input");
    this.input.type = "text";
    this.input.placeholder = "Write a comment...";
    this.input.required = true;

    const button = document.createElement("button");
    button.type = "submit";
    button.textContent = "Post";

    this.form.append(this.input, button);
    this.form.addEventListener("submit", (e) => this._onSubmit(e));

    this.list = document.createElement("ul");

    this.root.append(this.form, this.list);
  }

  _onSubmit(event) {
    event.preventDefault();
    const text = this.input.value.trim();
    if (!text) return;
    this.addComment(text);
    this.input.value = "";
  }

  addComment(text) {
    this.comments.push(text);
    this._renderComment(text);
  }

  _renderComment(text) {
    const item = document.createElement("li");

    const body = document.createElement("span");
    body.className = "comment-body";
    // textContent safely escapes the comment text; innerHTML would not.
    body.textContent = text;

    item.appendChild(body);
    this.list.appendChild(item);
  }
}

window.CommentBoard = CommentBoard;
