"use client";

import { useQuiz } from "@/app/hooks/useQuiz";
import QuizCard from "../Cards/QuizCard";

const PAGE_SIZE = 12;

export default function GetAllQuizzes() {
  const { quizzes, loading, error, page, hasMore, getQuizzes } = useQuiz();

  const handlePrevious = () => {
    if (page > 1) getQuizzes(page - 1, PAGE_SIZE);
  };

  const handleNext = () => {
    if (hasMore) getQuizzes(page + 1, PAGE_SIZE);
  };

  return (
    <>
      {loading && (
        <p className="col-span-full text-center text-gray-400">Chargement...</p>
      )}
      {error && (
        <p className="col-span-full text-center text-red-400">Erreur: {error}</p>
      )}
      {!loading && quizzes.length === 0 && (
        <p className="col-span-full text-center text-gray-500">Aucun quiz trouvé.</p>
      )}
      {quizzes.map((quiz) => (
        <QuizCard key={quiz.id} quizData={quiz} />
      ))}

      {/* Pagination */}
      {!loading && quizzes.length > 0 && (
        <div className="col-span-full flex items-center justify-center gap-4 mt-6">
          <button
            onClick={handlePrevious}
            disabled={page <= 1}
            className="px-4 py-2 rounded-lg bg-gray-800 border border-gray-700 text-white text-sm font-medium hover:bg-gray-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            ← Précédent
          </button>
          <span className="text-sm text-gray-400">
            Page {page}
          </span>
          <button
            onClick={handleNext}
            disabled={!hasMore}
            className="px-4 py-2 rounded-lg bg-gray-800 border border-gray-700 text-white text-sm font-medium hover:bg-gray-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            Suivant →
          </button>
        </div>
      )}
    </>
  );
}
