'use client';

import { useState } from 'react';

export default function CommentBoard() {
  const [comments, setComments] = useState([]);
  const [text, setText] = useState('');

  function addComment(e) {
    e.preventDefault();
    if (!text.trim()) return;
    setComments([...comments, text]);
    setText('');
  }

  return (
    <div>
      <form onSubmit={addComment}>
        <input value={text} onChange={(e) => setText(e.target.value)} placeholder="Write a comment" />
        <button type="submit">Post</button>
      </form>
      <ul>
        {comments.map((c, i) => (
          <li key={i}>{c}</li>
        ))}
      </ul>
    </div>
  );
}
