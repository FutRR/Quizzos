"use client";

import { useQuiz } from "@/app/hooks/useQuiz";
import Link from "next/dist/client/link";
import { useEffect, useState } from "react";

interface GetUserQuizzesProps {
  authorName: string;
}

export default function GetUserQuizzes({ authorName }: GetUserQuizzesProps) {
  const { loading, error, getQuizzesByAuthorName } = useQuiz();
  const [userQuizzes, setUserQuizzes] = useState<any[]>([]);

  useEffect(() => {
    const fetchUserQuizzes = async () => {
      const quizzes = await getQuizzesByAuthorName(authorName);
      setUserQuizzes(quizzes);
    };

    fetchUserQuizzes();
  }, [authorName, getQuizzesByAuthorName]);

  return (
    <div>
      <h1>Quizzes by {authorName}</h1>
      {loading && <p>Chargement...</p>}
      {error && <p>Erreur: {error}</p>}
      {userQuizzes && userQuizzes.length > 0
        ? userQuizzes.map((quiz) => (
            <div className="border p-4 rounded-lg" key={quiz.id}>
              <h2>{quiz.title}</h2>
              <p>{quiz.description}</p>
              <Link href={`/quizzes/${quiz.id}`}>Voir le quiz</Link>
            </div>
          ))
        : !loading && <p>Aucun quiz trouvé pour cet utilisateur.</p>}
    </div>
  );
}
