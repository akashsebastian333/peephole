const input = document.getElementById("comment-input");
const button = document.getElementById("comment-submit");
const list = document.getElementById("comment-list");

button.addEventListener("click", () => {
  const text = input.value;
  if (!text) return;
  const item = document.createElement("div");
  item.className = "comment";
  item.innerHTML = text;
  list.appendChild(item);
  input.value = "";
});
