"use client";

interface Answer {
  value: string;
  isCorrect: boolean;
}

interface TrueFalseAnswersProps {
  answers: Answer[];
  onAnswersChange: (answers: Answer[]) => void;
}

export default function TrueFalseAnswers({ answers, onAnswersChange }: TrueFalseAnswersProps) {
  const handleSelect = (index: number) => {
    onAnswersChange(
      answers.map((a, i) => ({ ...a, isCorrect: i === index }))
    );
  };

  return (
    <div className="grid grid-cols-2 gap-4 mt-4">
      {answers.map((answer, index) => (
        <button
          key={index}
          type="button"
          onClick={() => handleSelect(index)}
          className={`p-6 rounded-lg border-2 text-lg font-bold transition-all ${
            answer.isCorrect
              ? index === 0
                ? "border-green-500 bg-green-500/20 text-green-300"
                : "border-red-500 bg-red-500/20 text-red-300"
              : "border-gray-700 bg-gray-800 text-gray-400 hover:border-gray-500"
          }`}
        >
          {answer.value}
        </button>
      ))}
    </div>
  );
}
