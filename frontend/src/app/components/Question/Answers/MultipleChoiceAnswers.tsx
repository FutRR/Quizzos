"use client";

interface Answer {
  value: string;
  isCorrect: boolean;
}

interface MultipleChoiceAnswersProps {
  answers: Answer[];
  onAnswersChange: (answers: Answer[]) => void;
}

const answerColors = [
  "border-red-500/50 bg-red-500/10",
  "border-blue-500/50 bg-blue-500/10",
  "border-yellow-500/50 bg-yellow-500/10",
  "border-green-500/50 bg-green-500/10",
  "border-purple-500/50 bg-purple-500/10",
  "border-pink-500/50 bg-pink-500/10",
];

export default function MultipleChoiceAnswers({ answers, onAnswersChange }: MultipleChoiceAnswersProps) {
  const handleAdd = () => {
    onAnswersChange([...answers, { value: "", isCorrect: false }]);
  };

  const handleRemove = (index: number) => {
    if (answers.length <= 2) return;
    onAnswersChange(answers.filter((_, i) => i !== index));
  };

  const handleChange = (index: number, value: string) => {
    const updated = [...answers];
    updated[index] = { ...updated[index], value };
    onAnswersChange(updated);
  };

  const handleCorrectToggle = (index: number) => {
    const updated = [...answers];
    updated[index] = { ...updated[index], isCorrect: !updated[index].isCorrect };
    onAnswersChange(updated);
  };

  return (
    <div className="grid grid-cols-2 gap-2 text-center mt-4">
      {answers.map((answer, index) => (
        <div
          key={index}
          className={`relative bg-gray-800 p-2 rounded-lg border ${
            answer.isCorrect
              ? "border-green-500 bg-green-500/10"
              : answerColors[index % answerColors.length]
          } transition-colors`}
        >
          <input
            type="text"
            value={answer.value}
            onChange={(e) => handleChange(index, e.target.value)}
            placeholder={`Réponse ${index + 1}`}
            className="w-full bg-transparent text-white text-center placeholder-gray-400 focus:outline-none"
          />
          <div className="flex items-center justify-center gap-2 mt-1">
            <button
              type="button"
              onClick={() => handleCorrectToggle(index)}
              className={`text-xs px-2 py-0.5 rounded-full transition-colors ${
                answer.isCorrect
                  ? "bg-green-500 text-white"
                  : "bg-gray-700 text-gray-400 hover:bg-gray-600"
              }`}
            >
              {answer.isCorrect ? "✓ Correct" : "Correct ?"}
            </button>
            {answers.length > 2 && (
              <button
                type="button"
                onClick={() => handleRemove(index)}
                className="text-xs text-red-400 hover:text-red-300 transition-colors"
              >
                ✕
              </button>
            )}
          </div>
        </div>
      ))}
      <div className="col-span-2">
        <button type="button" onClick={handleAdd}>
          <img
            className="w-12 h-12 mx-auto hover:opacity-80 transition-opacity"
            src="/icons/Plus.svg"
            alt="Ajouter une reponse"
          />
        </button>
      </div>
    </div>
  );
}
