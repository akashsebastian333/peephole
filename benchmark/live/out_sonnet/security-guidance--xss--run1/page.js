'use client';
import { useState } from 'react';

export default function Page() {
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
      <h1>Comments</h1>
      <form onSubmit={addComment}>
        <input value={text} onChange={(e) => setText(e.target.value)} />
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
