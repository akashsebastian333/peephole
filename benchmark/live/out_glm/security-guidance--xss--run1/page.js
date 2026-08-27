const form = document.getElementById("comment-form");
const input = document.getElementById("comment-input");
const list = document.getElementById("comment-list");

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const text = input.value;
  if (!text.trim()) return;

  const item = document.createElement("li");
  item.className = "comment";

  const body = document.createElement("span");
  body.className = "comment-body";
  body.textContent = text; // textContent, not innerHTML: renders as inert text

  item.appendChild(body);
  list.appendChild(item);

  input.value = "";
});
