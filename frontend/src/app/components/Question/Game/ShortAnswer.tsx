"use client";

import { useState } from "react";

interface ShortAnswerProps {
  question: {
    id: number;
    text: string;
    imagesUrls: string[];
  };
  onAnswer: (value: string) => void;
}

export default function ShortAnswer({ question, onAnswer }: ShortAnswerProps) {
  const [value, setValue] = useState("");

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newValue = e.target.value;
    setValue(newValue);
    onAnswer(newValue);
  };

  return (
    <section className="mt-6 rounded-lg border border-gray-700 bg-gray-800 p-6 text-white">
      <h2 className="text-lg font-semibold">{question.text}</h2>
      <p className="mt-2 text-sm text-gray-400">Tapez votre réponse ci-dessous.</p>

      {question.imagesUrls.length > 0 && (
        <div className="mt-4 flex justify-center gap-3 overflow-x-auto">
          {question.imagesUrls.map((url, i) => (
            <img key={i} src={url} alt={`Image ${i + 1}`} className="rounded-lg max-h-72 object-contain border border-gray-600" />
          ))}
        </div>
      )}

      <input
        type="text"
        value={value}
        onChange={handleChange}
        placeholder="Votre réponse"
        className="mt-4 w-full rounded-lg border border-gray-600 bg-gray-700 px-4 py-3 text-white placeholder-gray-400 focus:border-indigo-500 focus:outline-none"
      />
    </section>
  );
}