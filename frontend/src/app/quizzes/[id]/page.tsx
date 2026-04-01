"use client";

import { use, useEffect, useState } from "react";
import { useQuiz } from "@/app/hooks/useQuiz";
import { useRouter } from "next/navigation";
import { useAuth } from "@/app/hooks/useAuth";
import Link from "next/link";
import DeleteQuizz from "@/app/components/Quizz/DeleteQuizz";
import TagBadge from "@/app/components/Tag/TagBadge";

const difficultyConfig: Record<string, { label: string; color: string; bg: string }> = {
  easy: { label: "Facile", color: "text-emerald-400", bg: "bg-emerald-400/10 border-emerald-400/20" },
  medium: { label: "Moyen", color: "text-amber-400", bg: "bg-amber-400/10 border-amber-400/20" },
  hard: { label: "Difficile", color: "text-rose-400", bg: "bg-rose-400/10 border-rose-400/20" },
};

function LoadingSkeleton() {
  return (
    <div className="max-w-4xl mx-auto animate-pulse">
      <div className="h-64 bg-gray-800 rounded-2xl mb-8" />
      <div className="h-10 bg-gray-800 rounded-lg w-2/3 mb-4" />
      <div className="h-5 bg-gray-800 rounded-lg w-1/2 mb-6" />
      <div className="flex gap-3 mb-6">
        <div className="h-8 w-20 bg-gray-800 rounded-full" />
        <div className="h-8 w-24 bg-gray-800 rounded-full" />
      </div>
    </div>
  );
}

export default function QuizDetail({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const { getQuizById, loading, error } = useQuiz();
  const [quiz, setQuiz] = useState<any>(null);
  const router = useRouter();
  const { user } = useAuth();

  const [showDeleteModal, setShowDeleteModal] = useState(false);

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

  if (loading) return <LoadingSkeleton />;

  if (error)
    return (
      <div className="max-w-4xl mx-auto">
        <div className="bg-rose-500/10 border border-rose-500/20 rounded-2xl p-6 text-center">
          <svg className="w-12 h-12 text-rose-400 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
          </svg>
          <p className="text-rose-400 font-medium">Erreur: {error}</p>
        </div>
      </div>
    );

  if (!quiz)
    return (
      <div className="max-w-4xl mx-auto">
        <div className="bg-gray-800/50 border border-gray-700 rounded-2xl p-12 text-center">
          <svg className="w-16 h-16 text-gray-600 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.879 7.519c1.171-1.025 3.071-1.025 4.242 0 1.172 1.025 1.172 2.687 0 3.712-.203.179-.43.326-.67.442-.745.361-1.45.999-1.45 1.827v.75M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9 5.25h.008v.008H12v-.008z" />
          </svg>
          <p className="text-gray-400 text-lg">Quiz non trouvé</p>
        </div>
      </div>
    );

  const difficulty = difficultyConfig[quiz.difficulty?.toLowerCase()] || {
    label: quiz.difficulty,
    color: "text-blue-400",
    bg: "bg-blue-400/10 border-blue-400/20",
  };

  const isOwner = user && quiz.authorName === user.userName;

  return (
    <div className="max-w-4xl mx-auto">
      {/* Hero Section */}
      <div className="relative rounded-2xl overflow-hidden mb-8">
        {quiz.imageUrl ? (
          <>
            <img
              src={quiz.imageUrl}
              alt={quiz.title}
              className="w-full h-72 object-cover"
            />
            <div className="absolute inset-0 bg-gradient-to-t from-gray-900 via-gray-900/60 to-transparent" />
            <div className="absolute bottom-0 left-0 right-0 p-8">
              <h1 className="text-4xl font-extrabold text-white tracking-tight mb-2 drop-shadow-lg">
                {quiz.title}
              </h1>
              <p className="text-gray-200 text-lg max-w-2xl leading-relaxed">
                {quiz.description}
              </p>
            </div>
          </>
        ) : (
          <div className="bg-gradient-to-br from-indigo-600/20 via-gray-900 to-purple-600/20 border border-gray-800 rounded-2xl p-10">
            <h1 className="text-4xl font-extrabold text-white tracking-tight mb-3">
              {quiz.title}
            </h1>
            <p className="text-gray-400 text-lg max-w-2xl leading-relaxed">
              {quiz.description}
            </p>
          </div>
        )}
      </div>

      {/* Meta Info Bar */}
      <div className="flex flex-wrap items-center gap-4 mb-6">
        {/* Difficulty Badge */}
        <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-sm font-semibold border ${difficulty.bg} ${difficulty.color}`}>
          <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.828a1 1 0 101.415-1.414L11 9.586V6z" clipRule="evenodd" />
          </svg>
          {difficulty.label}
        </span>

        {/* Author */}
        <Link
          href={`/profile/${quiz.authorName}`}
          className="inline-flex items-center gap-2 text-sm text-gray-400 hover:text-white transition-colors group"
        >
          <span className="w-7 h-7 rounded-full bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400 text-xs font-bold group-hover:bg-indigo-500/30 transition-colors">
            {quiz.authorName?.charAt(0).toUpperCase()}
          </span>
          <span>{quiz.authorName}</span>
        </Link>

        {/* Separator */}
        <span className="w-px h-5 bg-gray-700" />

        {/* Date */}
        <span className="inline-flex items-center gap-1.5 text-sm text-gray-500">
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M6.75 3v2.25M17.25 3v2.25M3 18.75V7.5a2.25 2.25 0 012.25-2.25h13.5A2.25 2.25 0 0121 7.5v11.25m-18 0A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75m-18 0v-7.5A2.25 2.25 0 015.25 9h13.5A2.25 2.25 0 0121 11.25v7.5" />
          </svg>
          {new Date(quiz.createdAt).toLocaleDateString("fr-FR", {
            day: "numeric",
            month: "long",
            year: "numeric",
          })}
        </span>

        {/* Questions count */}
        {quiz.questions?.length > 0 && (
          <>
            <span className="w-px h-5 bg-gray-700" />
            <span className="inline-flex items-center gap-1.5 text-sm text-gray-500">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M8.625 12a.375.375 0 11-.75 0 .375.375 0 01.75 0zm0 0H8.25m4.125 0a.375.375 0 11-.75 0 .375.375 0 01.75 0zm0 0H12m4.125 0a.375.375 0 11-.75 0 .375.375 0 01.75 0zm0 0h-.375M21 12c0 4.556-4.03 8.25-9 8.25a9.764 9.764 0 01-2.555-.337A5.972 5.972 0 015.41 20.97a5.969 5.969 0 01-.474-.065 4.48 4.48 0 00.978-2.025c.09-.457-.133-.901-.467-1.226C3.93 16.178 3 14.189 3 12c0-4.556 4.03-8.25 9-8.25s9 3.694 9 8.25z" />
              </svg>
              {quiz.questions.length} question{quiz.questions.length > 1 ? "s" : ""}
            </span>
          </>
        )}
      </div>

      {/* Tags */}
      {quiz.tags?.length > 0 && (
        <div className="flex flex-wrap gap-2 mb-8">
          {quiz.tags.map((tag: any) => (
            <TagBadge key={tag.id} tag={tag} size="md" />
          ))}
        </div>
      )}

      {/* Owner Actions & Questions */}
      {isOwner && (
        <>
          {/* Action Buttons */}
          <div className="flex flex-wrap gap-3 mb-10">
            <button
              onClick={() => router.push(`/quizzes/${id}/add-question`)}
              className="inline-flex items-center gap-2 px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-semibold rounded-xl transition-colors shadow-lg shadow-indigo-600/20"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.5v15m7.5-7.5h-15" />
              </svg>
              Ajouter une question
            </button>
            <button
              onClick={() => router.push(`/quizzes/${id}/edit-quiz`)}
              className="inline-flex items-center gap-2 px-5 py-2.5 bg-gray-800 hover:bg-gray-700 text-white text-sm font-semibold rounded-xl border border-gray-700 transition-colors"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10" />
              </svg>
              Modifier le quiz
            </button>
            <button
              onClick={() => setShowDeleteModal(true)}
              className="inline-flex items-center gap-2 px-5 py-2.5 bg-rose-600/10 hover:bg-rose-600 text-rose-400 hover:text-white text-sm font-semibold rounded-xl border border-rose-600/20 hover:border-rose-600 transition-all"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" />
              </svg>
              Supprimer
            </button>
            <DeleteQuizz
              isOpen={showDeleteModal}
              onClose={() => setShowDeleteModal(false)}
              quizId={id}
            />
          </div>

          {/* Questions Section */}
          <div>
            <div className="flex items-center gap-3 mb-5">
              <h2 className="text-xl font-bold text-white">Questions</h2>
              <span className="px-2.5 py-0.5 text-xs font-semibold rounded-full bg-gray-800 text-gray-400 border border-gray-700">
                {quiz.questions?.length || 0}
              </span>
            </div>

            {quiz.questions?.length > 0 ? (
              <div className="space-y-3">
                {quiz.questions.map((question: any, index: number) => (
                  <div
                    key={question.id}
                    className="group bg-gray-800/50 hover:bg-gray-800 border border-gray-700/50 hover:border-gray-600 rounded-xl p-5 transition-all duration-200"
                  >
                    <div className="flex items-start gap-4">
                      <span className="shrink-0 w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 text-sm font-bold">
                        {index + 1}
                      </span>
                      <div className="flex-1 min-w-0">
                        <h3 className="font-semibold text-white group-hover:text-indigo-300 transition-colors">
                          {question.text}
                        </h3>
                        <p className="text-xs text-gray-500 mt-1.5 flex items-center gap-1.5">
                          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.568 3H5.25A2.25 2.25 0 003 5.25v4.318c0 .597.237 1.17.659 1.591l9.581 9.581c.699.699 1.78.872 2.607.33a18.095 18.095 0 005.223-5.223c.542-.827.369-1.908-.33-2.607L11.16 3.66A2.25 2.25 0 009.568 3z" />
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 6h.008v.008H6V6z" />
                          </svg>
                          {question.type}
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="bg-gray-800/30 border border-dashed border-gray-700 rounded-xl p-8 text-center">
                <svg className="w-12 h-12 text-gray-600 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 4.5v15m7.5-7.5h-15" />
                </svg>
                <p className="text-gray-500">Aucune question pour le moment</p>
                <button
                  onClick={() => router.push(`/quizzes/${id}/add-question`)}
                  className="mt-3 text-sm text-indigo-400 hover:text-indigo-300 font-medium transition-colors"
                >
                  Ajouter votre première question
                </button>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
