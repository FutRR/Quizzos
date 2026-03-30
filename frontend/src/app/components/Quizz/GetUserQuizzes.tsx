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
    <div>
      <h1>Quizzes by {authorName} :</h1>
      {loading && <p>Chargement...</p>}
      {error && <p>Erreur: {error}</p>}
      {userQuizzes && userQuizzes.length > 0
        ? userQuizzes.map((quiz) => (
            <QuizCard key={quiz.id} quizData={quiz} />

            // <div className="border p-4 rounded-lg" key={quiz.id}>
            //   <h2>{quiz.title}</h2>
            //   <p>{quiz.description}</p>
            //   {quiz.tags && quiz.tags.length > 0 && (
            //     <div className="flex flex-wrap gap-1.5 mt-3">
            //       {quiz.tags.map((tag: any) => (
            //         <TagBadge key={tag.id} tag={tag} />
            //       ))}
            //     </div>
            //   )}
            //   <Link href={`/quizzes/${quiz.id}`}>Voir le quiz</Link>
            // </div>
          ))
        : !loading && <p>Aucun quiz trouvé pour cet utilisateur.</p>}
    </div>
  );
}
