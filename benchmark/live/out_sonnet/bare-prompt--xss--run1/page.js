'use client';

import { useState } from 'react';

export default function CommentBoard() {
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
    <div>
      <form onSubmit={addComment}>
        <input
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Add a comment"
        />
        <button type="submit">Post</button>
      </form>
      <ul>
        {comments.map((comment, i) => (
          <li key={i}>{comment}</li>
        ))}
      </ul>
    </div>
  );
}
