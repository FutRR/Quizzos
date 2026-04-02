"use client";

import { use, useEffect, useState } from "react";
import { useQuiz } from "@/app/hooks/useQuiz";
import MultipleChoice from "@/app/components/Question/Game/MultipleChoice";
import ShortAnswer from "@/app/components/Question/Game/ShortAnswer";
import TrueOrFalse from "@/app/components/Question/Game/TrueOrFalse";

interface Answer {
  id: number;
  value: string;
  isCorrect: boolean;
}

interface Question {
  id: number;
  text: string;
  type: string; // "MultipleChoice" | "TrueFalse" | "ShortAnswer"
  answers: Answer[];
  imagesUrls: string[];
  isTimed: boolean;
  timeLimit: number | null;
}

export default function QuizPlay({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { getQuizById, loading, error } = useQuiz();

  const [quiz, setQuiz] = useState<any>(null);
  const [started, setStarted] = useState(false);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [userAnswers, setUserAnswers] = useState<Record<number, any>>({});

  useEffect(() => {
    const load = async () => {
      try {
        const data = await getQuizById(id);
        setQuiz(data);
      } catch (err) {
        console.error("Failed to load quiz:", err);
      }
    };
    load();
  }, [id, getQuizById]);

  if (loading) return <p className="text-white text-center mt-10">Chargement...</p>;
  if (error) return <p className="text-red-400 text-center mt-10">Erreur : {error}</p>;
  if (!quiz) return null;

  const questions: Question[] = quiz.questions ?? [];
  const currentQuestion = questions[currentIndex];
  const isLast = currentIndex === questions.length - 1;

  // --- Écran de démarrage ---
  if (!started) {
    return (
      <div className="max-w-2xl mx-auto mt-20 text-center text-white">
        <h1 className="text-3xl font-bold">{quiz.title}</h1>
        <p className="mt-4 text-gray-400">{quiz.description}</p>
        <p className="mt-2 text-sm text-gray-500">{questions.length} question(s)</p>
        <button
          onClick={() => setStarted(true)}
          className="mt-8 px-8 py-3 bg-indigo-600 hover:bg-indigo-500 rounded-lg font-semibold transition-colors"
        >
          Commencer le quiz
        </button>
      </div>
    );
  }

  // --- Callback réponse ---
  const handleAnswer = (value: any) => {
    setUserAnswers((prev) => ({ ...prev, [currentQuestion.id]: value }));
  };

  const handleNext = () => {
    if (isLast) {
      // TODO: écran résultat / soumission
      console.log("Quiz terminé", userAnswers);
      return;
    }
    setCurrentIndex((i) => i + 1);
  };

  // --- Rendu dynamique du composant selon le type ---
  const renderQuestion = () => {
    switch (currentQuestion.type) {
      case "MultipleChoice":
        return <MultipleChoice question={currentQuestion} onAnswer={handleAnswer} />;
      case "TrueFalse":
        return <TrueOrFalse question={currentQuestion} onAnswer={handleAnswer} />;
      case "ShortAnswer":
        return <ShortAnswer question={currentQuestion} onAnswer={handleAnswer} />;
      default:
        return <p className="text-red-400">Type de question inconnu : {currentQuestion.type}</p>;
    }
  };

  return (
    <div className="max-w-2xl mx-auto mt-10 text-white">
      {/* Progression */}
      <div className="flex items-center justify-between mb-4">
        <span className="text-sm text-gray-400">
          Question {currentIndex + 1} / {questions.length}
        </span>
        <div className="flex-1 mx-4 h-2 bg-gray-700 rounded-full overflow-hidden">
          <div
            className="h-full bg-indigo-500 transition-all"
            style={{ width: `${((currentIndex + 1) / questions.length) * 100}%` }}
          />
        </div>
      </div>

      {/* Composant question dynamique */}
      {renderQuestion()}

      {/* Navigation */}
      <button
        onClick={handleNext}
        disabled={userAnswers[currentQuestion.id] === undefined}
        className="mt-6 w-full py-3 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 rounded-lg font-semibold transition-colors"
      >
        {isLast ? "Terminer" : "Suivant"}
      </button>
    </div>
  );
}