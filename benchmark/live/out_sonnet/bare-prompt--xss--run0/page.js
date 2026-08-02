'use client';

import { useState } from 'react';

export default function Page() {
  const [comments, setComments] = useState([]);
  const [text, setText] = useState('');

  function addComment(e) {
    e.preventDefault();
    const trimmed = text.trim();
    if (!trimmed) return;
    setComments((prev) => [...prev, trimmed]);
    setText('');
  }

  return (
    <main>
      <h1>Comment Board</h1>
      <form onSubmit={addComment}>
        <input
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Write a comment"
        />
        <button type="submit">Post</button>
      </form>
      <ul>
        {comments.map((comment, i) => (
          <li key={i}>{comment}</li>
        ))}
      </ul>
    </main>
  );
}
