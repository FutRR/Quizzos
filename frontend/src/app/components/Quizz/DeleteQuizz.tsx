"use client";

import { useRouter } from "next/navigation";
import { useQuiz } from "../../hooks/useQuiz";

interface DeleteQuizzModalProps {
  isOpen: boolean;
  onClose: () => void;
  quizId: string;
}

export default function DeleteQuizz({
  isOpen,
  onClose,
  quizId,
}: DeleteQuizzModalProps) {
  const router = useRouter();
  const { deleteQuiz, loading, error } = useQuiz();

  if (!isOpen) return null;

  const handleDelete = async () => {
    try {
      await deleteQuiz(quizId);
      router.push("/quizzes");
    } catch {
      // error is already set in useQuiz state
    }
  };

  return (
    <>
      {error && <p>{error}</p>}
      {loading && <p>Loading...</p>}

      <div className="fixed inset-0 z-50 flex items-center justify-center">
        {/* Overlay */}
        <div
          className="fixed inset-0 bg-black/60 backdrop-blur-sm"
          onClick={onClose}
        />
        {/* Modal content */}
        <div className="relative bg-gray-900 rounded-xl border border-gray-700 p-6 w-20% max-h-[90vh] overflow-y-auto mx-4 shadow-2xl">
          <div className="flex flex-col items-center justify-between mb-4">
            <h1 className="text-xl font-bold text-white">Supprimer un quiz</h1>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-white transition-colors p-1"
            >
              <svg
                className="w-6 h-6"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M6 18L18 6M6 6l12 12"
                />
              </svg>
            </button>
            <div>
              <button
                onClick={handleDelete}
                className="mt-4 bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded transition-colors"
              >
                Confirmer la suppression
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
