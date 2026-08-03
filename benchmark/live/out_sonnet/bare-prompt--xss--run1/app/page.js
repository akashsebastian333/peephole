'use client';

import { useState } from 'react';

export default function Page() {
  const [comments, setComments] = useState([]);
  const [text, setText] = useState('');

  function addComment(e) {
    e.preventDefault();
    if (!text.trim()) return;
    setComments((prev) => [...prev, text]);
    setText('');
  }

  return (
    <main>
      <h1>Comment Board</h1>
      <form onSubmit={addComment}>
        <input
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Add a comment"
        />
        <button type="submit">Post</button>
      </form>
      <ul>
        {comments.map((c, i) => (
          // React escapes text content here, no innerHTML/dangerouslySetInnerHTML with user input.
          <li key={i}>{c}</li>
        ))}
      </ul>
    </main>
  );
}
