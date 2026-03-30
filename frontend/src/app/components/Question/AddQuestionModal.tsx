"use client";

import CreateQuestion from "./CreateQuestion";

interface AddQuestionModalProps {
  isOpen: boolean;
  onClose: () => void;
  quizId: string;
}

export default function AddQuestionModal({ isOpen, onClose, quizId }: AddQuestionModalProps) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Overlay */}
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />
      {/* Modal content */}
      <div className="relative z-10 bg-gray-900 rounded-xl border border-gray-700 p-6 w-full max-w-4xl max-h-[90vh] overflow-y-auto mx-4 shadow-2xl">
        <div className="flex items-center justify-between mb-4">
          <h1 className="text-xl font-bold text-white">Ajouter une question</h1>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white transition-colors p-1"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <CreateQuestion quizId={quizId} />
        <div className="flex justify-end gap-3 mt-6">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm font-medium text-gray-300 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors"
          >
            Terminer
          </button>
        </div>
      </div>
    </div>
  );
}
