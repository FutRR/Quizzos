"use client";

import { use, useEffect, useState } from "react";
import { useQuiz } from "@/app/hooks/useQuiz";
import MultipleChoice from "@/app/components/Question/Game/MultipleChoice";
import ShortAnswer from "@/app/components/Question/Game/ShortAnswer";
import TrueOrFalse from "@/app/components/Question/Game/TrueOrFalse";
import quizAttemptService from "@/app/services/QuizAttemptService";
import { QuizAttemptResult, SubmitQuizPayload } from "@/app/types/quizAttemptsType";

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
  const [result, setResult] = useState<QuizAttemptResult | null>(null);
  const [submitting, setSubmitting] = useState(false);

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

// --- Écran résultat ---
if (result) {
  return (
    <div className="max-w-2xl mx-auto mt-20 text-center text-white">
      <h1 className="text-3xl font-bold">Résultat</h1>
      <p className="mt-4 text-5xl font-bold text-indigo-400">
        {result.scorePercent}%
      </p>
      <p className="mt-2 text-gray-400">
        {result.correctAnswers} / {result.totalQuestions} bonnes réponses
      </p>
      {result.isFirstAttempt && (
        <p className="mt-2 text-sm text-yellow-400">🎯 Première tentative !</p>
      )}
      {result.isNewBestScore && (
        <p className="mt-2 text-sm text-green-400">🏆 Nouveau meilleur score !</p>
      )}

      {/* Détail par question */}
      <div className="mt-8 text-left space-y-3">
        {result.results.map((r, i) => (
          <div
            key={r.questionId}
            className={`p-3 rounded-lg border ${
              r.isCorrect
                ? "border-green-600 bg-green-900/20"
                : "border-red-600 bg-red-900/20"
            }`}
          >
            <span className="font-medium">
              Q{i + 1}: {r.isCorrect ? "✅ Correct" : "❌ Incorrect"}
            </span>
          </div>
        ))}
      </div>

      <button
        onClick={() => window.location.href = `/quizzes/${id}`}
        className="mt-8 px-8 py-3 bg-indigo-600 hover:bg-indigo-500 rounded-lg font-semibold transition-colors"
      >
        Retour au quiz
      </button>
    </div>
  );
}

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

  const handleNext = async () => {
    if (!isLast) {
      setCurrentIndex((i) => i + 1);
      return;
    }
  
  // Payload
  const payload: SubmitQuizPayload = {
      quizId: Number(id),
      answers: questions.map((q) => {
        const answer = userAnswers[q.id];
        // MultipleChoice et TrueFalse stockent un answerId (number)
        // ShortAnswer stocke une string — on cherche l'answer correspondante
        let selectedOptionIds: number[] = [];
        if (typeof answer === "number") {
          selectedOptionIds = [answer];
        } else if (typeof answer === "string") {
          const match = q.answers.find(
            (a) => a.value.toLowerCase() === answer.toLowerCase()
          );
          if (match) selectedOptionIds = [match.id];
        }
        return { questionId: q.id, selectedOptionIds };
      }),
    };

      setSubmitting(true);
  try {
    const res = await quizAttemptService.submitQuiz(payload);
    setResult(res);
  } catch (err) {
    console.error("Erreur soumission quiz:", err);
  } finally {
    setSubmitting(false);
  }
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
        disabled={userAnswers[currentQuestion.id] === undefined || submitting}
        className="mt-6 w-full py-3 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 rounded-lg font-semibold transition-colors"
      >
        {isLast ? (submitting ? "Envoi..." : "Terminer") : "Suivant"}
      </button>
    </div>
  );
}