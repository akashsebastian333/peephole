'use client';

import { useState, useRef } from 'react';

export default function CommentBoard() {
  const [comments, setComments] = useState([]);
  const inputRef = useRef(null);
  const listRef = useRef(null);

  function addComment(e) {
    e.preventDefault();
    const text = inputRef.current.value.trim();
    if (!text) return;

    // ponytail: render via textContent, not innerHTML — keeps user text as data, never as markup (CWE-79)
    const el = document.createElement('li');
    el.textContent = text;
    listRef.current.appendChild(el);

    setComments((prev) => [...prev, text]);
    inputRef.current.value = '';
  }

  return (
    <div>
      <h1>Comment Board</h1>
      <form onSubmit={addComment}>
        <input ref={inputRef} type="text" placeholder="Write a comment" />
        <button type="submit">Post</button>
      </form>
      <ul ref={listRef}>
        {comments.map((c, i) => (
          <li key={i}>{c}</li>
        ))}
      </ul>
    </div>
  );
}
