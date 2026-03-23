"use client";

import { use, useEffect, useState } from "react";
import { useQuiz } from "@/app/hooks/useQuiz";
import { useRouter } from "next/navigation";

export default function QuizDetail({ params }: { params: Promise<{ id: string }> }) {
    const { id } = use(params);
    const { getQuizById, loading, error } = useQuiz();
    const [quiz, setQuiz] = useState<any>(null);
    const router = useRouter();

    useEffect(() => {
        const loadQuiz = async () => {
            try {
                const data = await getQuizById(id);
                setQuiz(data);
            } catch (err) {
                console.error("Failed to load quiz:", err);
            }
        };
        loadQuiz();
    }, [id, getQuizById]);

    if (loading) return <p>Chargement...</p>;
    if (error) return <p className="text-red-500">Erreur: {error}</p>;
    if (!quiz) return <p>Quiz non trouvé</p>;

    return (
        <div className="p-6">
            <h1 className="text-3xl font-bold mb-4">{quiz.title}</h1>
            <p className="text-gray-600 mb-2">{quiz.description}</p>
            <div className="flex gap-4 mb-4">
                <span className="badge">Difficulté: {quiz.difficulty}</span>
                <span className="text-sm text-gray-500">Par {quiz.authorName}</span>
            </div>
            {quiz.imageUrl && (
                <img src={quiz.imageUrl} alt={quiz.title} className="w-full max-w-2xl rounded" />
            )}
            <div className="mt-4">
                <p className="text-sm text-gray-400">
                    Créé le: {new Date(quiz.createdAt).toLocaleDateString()}
                </p>
            </div>
            <div className="flex gap-4">
                <button onClick={() => router.push(`/quizzes/${id}/add-question`)} className="btn btn-primary">
                    Ajouter une question
                </button>
                <button onClick={() => router.push(`/quizzes/${id}/edit-quiz`)} className="btn btn-primary">
                    Modifier le quiz
                </button>
            </div>
        </div>
    );
}