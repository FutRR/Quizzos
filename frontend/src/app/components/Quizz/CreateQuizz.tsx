"use client";

import { useState } from "react";
import { useQuiz } from "@/app/hooks/useQuiz";
import { useRouter } from "next/navigation";
import TagInput from "../Tag/TagInput";
import ImageUpload from "../Images/ImageUpload";
import { Tag } from "@/app/types/tagTypes";
import AddQuestionModal from "../Question/AddQuestionModal";

export default function CreateQuizz() {
  const router = useRouter();
  const { createQuiz, loading, error } = useQuiz();

  // Etats pour les champs du formulaire
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [difficulty, setDifficulty] = useState("");
  const [selectedTags, setSelectedTags] = useState<Tag[]>([]);
  const [imageUrl, setImageUrl] = useState("");
  const [showModal, setShowModal] = useState(false);
  const [createdQuizId, setCreatedQuizId] = useState<string | null>(null);

  const handleSubmit = async (e: React.SubmitEvent<HTMLFormElement>) => {
    e.preventDefault();
    try {
      const newQuiz = await createQuiz({
        title,
        description,
        difficulty,
        tagIds: selectedTags.map((tag) => tag.id),
        imageUrl,
      });
      if (newQuiz) {
        setCreatedQuizId(newQuiz.id);
        setShowModal(true);
      }
    } catch {
      // error is already set in useQuiz state
    }
  };

  const handleModalClose = () => {
    setShowModal(false);
    if (createdQuizId) {
      router.push(`/quizzes/${createdQuizId}`);
    }
  };

  return (
    <>
      {error && <p>{error}</p>}
      {loading && <p>Loading...</p>}
      <div>
        <h1>Create Quizz</h1>
        <form onSubmit={handleSubmit}>
          <input
            type="text"
            placeholder="Title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
          />
          <input
            type="text"
            placeholder="Description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />

          <select
            value={difficulty}
            onChange={(e) => setDifficulty(e.target.value)}
          >
            <option value="">Select Difficulty</option>
            <option value="Easy">Easy</option>
            <option value="Medium">Medium</option>
            <option value="Hard">Hard</option>
          </select>
          <TagInput
            selectedTags={selectedTags}
            onTagsChange={setSelectedTags}
            maxTags={5}
            placeholder="Ajouter des tags..."
          />
          <ImageUpload
            onImageUploaded={setImageUrl}
            currentImageUrl={imageUrl}
          />
          <button type="submit">Create</button>
        </form>
      </div>
      {createdQuizId && (
        <AddQuestionModal
          isOpen={showModal}
          onClose={handleModalClose}
          quizId={createdQuizId}
        />
      )}
    </>
  );
}
