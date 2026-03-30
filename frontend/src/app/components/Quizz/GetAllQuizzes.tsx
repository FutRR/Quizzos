"use client";

import { useQuiz } from "@/app/hooks/useQuiz";
import Link from "next/link";
import { TagBadge } from "../Tag";
import QuizCard from "../Cards/QuizCard";

export default function GetAllQuizzes() {
  const { quizzes, loading, error } = useQuiz();
  return (
    <>
      {loading && <p>Chargement...</p>}
      {error && <p>Erreur: {error}</p>}
      {quizzes &&
        quizzes.map((quiz) => (
          <QuizCard key={quiz.id} quizData={quiz} />
          // <div className="border p-4 rounded-lg" key={quiz.id}>
          //   <h2>{quiz.title}</h2>
          //   <p>{quiz.description}</p>
          //   <Link href={`/quizzes/${quiz.id}`}>Voir le quiz</Link>
          //   {quiz.tags && quiz.tags.length > 0 && (
          //     <div className="flex flex-wrap gap-1.5 mt-3">
          //       {quiz.tags.map((tag: any) => (
          //         <TagBadge key={tag.id} tag={tag} />
          //       ))}
          //     </div>
          //   )}
          // </div>
        ))}
    </>
  );
}
