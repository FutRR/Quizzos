"use client";

import { useQuiz } from "@/app/hooks/useQuiz";
import Link from "next/dist/client/link";
import { useEffect, useState } from "react";
import { TagBadge } from "../Tag";
import QuizCard from "../Cards/QuizCard";

interface GetUserQuizzesProps {
  authorName: string;
}

export default function GetUserQuizzes({ authorName }: GetUserQuizzesProps) {
  const { loading, error, getQuizzesByAuthorName } = useQuiz();
  const [userQuizzes, setUserQuizzes] = useState<any[]>([]);

  useEffect(() => {
    const fetchUserQuizzes = async () => {
      const quizzes = await getQuizzesByAuthorName(authorName);
      console.log("User quizzes data:", quizzes);
      setUserQuizzes(quizzes);
    };

    fetchUserQuizzes();
  }, [authorName, getQuizzesByAuthorName]);

  return (
    <div className="flex flex-col align-center gap-8">
      {loading && <p>Chargement...</p>}
      {error && <p>Erreur: {error}</p>}
      {userQuizzes && userQuizzes.length > 0
        ? userQuizzes.map((quiz) => <QuizCard key={quiz.id} quizData={quiz} />)
        : !loading && <p>Aucun quiz trouvé pour cet utilisateur.</p>}
    </div>
  );
}
