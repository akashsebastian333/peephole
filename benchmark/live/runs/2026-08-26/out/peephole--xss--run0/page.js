document.addEventListener('DOMContentLoaded', () => {
  const form = document.querySelector('form');
  const input = document.querySelector('input[name="comment"]');
  const list = document.querySelector('.comments-list');

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const comment = input.value.trim();
    if (comment) {
      const el = document.createElement('div');
      el.className = 'comment';
      el.textContent = comment;
      list.appendChild(el);
      input.value = '';
    }
  });
});
