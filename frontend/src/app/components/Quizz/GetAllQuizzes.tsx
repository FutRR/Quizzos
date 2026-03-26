import { useQuiz } from "@/app/hooks/useQuiz";
import Link from "next/link";

export default function GetAllQuizzes() {
  const { quizzes, loading, error } = useQuiz();
  return (
    <>
      {loading && <p>Chargement...</p>}
      {error && <p>Erreur: {error}</p>}
      {quizzes && quizzes.map((quiz) => (
        <div className="border p-4 rounded-lg" key={quiz.id}>
          <h2>{quiz.title}</h2>
          <p>{quiz.description}</p>
          <Link href={`/quizzes/${quiz.id}`}>Voir le quiz</Link>
        </div>
      ))}
    </>
  )
}