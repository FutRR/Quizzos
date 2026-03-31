"use client";

import { use, useEffect, useState } from "react";
import { useQuiz } from "@/app/hooks/useQuiz";
import { useRouter } from "next/navigation";
import { useAuth } from "@/app/hooks/useAuth";
import Link from "next/link";

export default function QuizDetail({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const { getQuizById, loading, error } = useQuiz();
  const [quiz, setQuiz] = useState<any>(null);
  const router = useRouter();
  const { user } = useAuth();

  useEffect(() => {
    const loadQuiz = async () => {
      try {
        const data = await getQuizById(id);
        setQuiz(data);
      } catch (err) {
        console.error("Failed to load quiz:", err);
      }
    };
    loadQuiz();
  }, [id, getQuizById]);

  if (loading) return <p>Chargement...</p>;
  if (error) return <p className="text-red-500">Erreur: {error}</p>;
  if (!quiz) return <p>Quiz non trouvé</p>;

  return (
    <div className="p-6">
      <h1 className="text-3xl font-bold mb-4">{quiz.title}</h1>
      <p className="text-gray-600 mb-2">{quiz.description}</p>
      <div className="flex gap-4 mb-4">
        <span className="badge">Difficulté: {quiz.difficulty}</span>
        <Link
          href={`/profile/${quiz.authorName}`}
          className="text-sm opacity-90"
        >
          By {quiz.authorName}
        </Link>{" "}
      </div>
      {quiz.imageUrl && (
        <img
          src={quiz.imageUrl}
          alt={quiz.title}
          className="w-full max-w-2xl rounded"
        />
      )}
      <div className="mt-4">
        <p className="text-sm text-gray-400">
          Créé le: {new Date(quiz.createdAt).toLocaleDateString()}
        </p>
      </div>
      {user && quiz.authorName === user.userName && (
        <div className="mt-6">
          <div className="mt-4">
            <h2 className="text-xl font-bold mb-2">Questions</h2>
            <div className="space-y-4">
              {quiz.questions.map((question: any) => (
                <div key={question.id} className="border p-4 rounded">
                  <h3 className="font-bold">{question.text}</h3>
                  <p className="text-sm text-gray-500">Type: {question.type}</p>
                </div>
              ))}
            </div>
          </div>
          <div className="flex gap-4">
            <button
              onClick={() => router.push(`/quizzes/${id}/add-question`)}
              className="btn btn-primary"
            >
              Ajouter une question
            </button>
            <button
              onClick={() => router.push(`/quizzes/${id}/edit-quiz`)}
              className="btn btn-primary"
            >
              Modifier le quiz
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
