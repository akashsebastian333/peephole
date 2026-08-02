'use client';

import { useRef, useState } from 'react';

export default function Page() {
  const [comments, setComments] = useState([]);
  const inputRef = useRef(null);

  function addComment(e) {
    e.preventDefault();
    const text = inputRef.current.value.trim();
    if (!text) return;
    setComments((prev) => [...prev, text]);
    inputRef.current.value = '';
  }

  return (
    <main>
      <h1>Comment Board</h1>
      <form onSubmit={addComment}>
        <input ref={inputRef} type="text" placeholder="Write a comment..." />
        <button type="submit">Post</button>
      </form>
      <ul>
        {comments.map((c, i) => (
          // React escapes text content here, so this is not vulnerable to XSS
          // the way element.innerHTML = commentText would be.
          <li key={i}>{c}</li>
        ))}
      </ul>
    </main>
  );
}
