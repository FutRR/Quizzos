"use client";

interface Answer {
  value: string;
  isCorrect: boolean;
}

interface ShortAnswerInputProps {
  answers: Answer[];
  onAnswersChange: (answers: Answer[]) => void;
}

export default function ShortAnswerInput({ answers, onAnswersChange }: ShortAnswerInputProps) {
  const handleChange = (value: string) => {
    onAnswersChange([{ value, isCorrect: true }]);
  };

  return (
    <div className="mt-4 bg-gray-800 p-6 rounded-lg border border-gray-700">
      <h3 className="text-sm font-medium text-gray-400 mb-2">Réponse attendue</h3>
      <input
        type="text"
        value={answers[0]?.value || ""}
        onChange={(e) => handleChange(e.target.value)}
        placeholder="Tapez la bonne réponse..."
        className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:border-indigo-500 transition-colors"
      />
    </div>
  );
}
