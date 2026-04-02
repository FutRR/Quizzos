"use client";

import { useState } from "react";

interface MultipleChoiceProps {
  question: {
    id: number;
    text: string;
    answers: { id: number; value: string; isCorrect: boolean }[];
    imagesUrls: string[];
  };
  onAnswer: (answerId: number) => void;
}

export default function MultipleChoice({ question, onAnswer }: MultipleChoiceProps) {
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);

  return (
    <section className="mt-6 rounded-lg border border-gray-700 bg-gray-800 p-6 text-white">
      <h2 className="text-lg font-semibold">{question.text}</h2>
      <p className="mt-2 text-sm text-gray-400">Sélectionnez une réponse pour continuer.</p>

      {question.imagesUrls.length > 0 && (
        <div className="mt-4 flex justify-center gap-3 overflow-x-auto">
          {question.imagesUrls.map((url, i) => (
            <img key={i} src={url} alt={`Image ${i + 1}`} className="rounded-lg max-h-72 object-contain border border-gray-600" />
          ))}
        </div>
      )}

      <div className="mt-4 grid gap-3 sm:grid-cols-2">
        {question.answers.map((answer, index) => (
          <button
            key={answer.id}
            type="button"
            onClick={() => {
              setSelectedIndex(index);
              onAnswer(answer.id);
            }}
            className={`rounded-lg border px-4 py-3 text-left transition-colors ${
              selectedIndex === index
                ? "border-indigo-500 bg-indigo-500/20 text-indigo-100"
                : "border-gray-600 bg-gray-700 text-gray-200 hover:border-gray-500"
            }`}
          >
            {answer.value}
          </button>
        ))}
      </div>
    </section>
  );
}
