"use client";

import { useState } from "react";
import { useQuiz } from "@/app/hooks/useQuiz";
import { useRouter } from "next/navigation";



export default function CreateQuizz() {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [difficulty, setDifficulty] = useState("");
  const [imageUrl, setImageUrl] = useState("");

  return (
    <div>
      <h1>Create Quizz</h1>
      <form>
        <input type="text" placeholder="Title" />
        <input type="text" placeholder="Description" />
        <input type="text" placeholder="Difficulty" />
        <input type="text" placeholder="Image URL" />
        <button type="submit">Create</button>
      </form>
    </div>
  );
}
