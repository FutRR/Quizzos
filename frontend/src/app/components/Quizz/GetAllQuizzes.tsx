"use client";

import QuizCard from "../Cards/QuizCard";

interface GetAllQuizzesProps {
  quizzes: any[];
  loading: boolean;
  error: string | null;
  page: number;
  hasMore: boolean;
  searchQuery: string;
  onPrevious: () => void;
  onNext: () => void;
}

// Icons
const SearchXIcon = ({ className }: { className?: string }) => (
  <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
  </svg>
);

// Skeleton component for loading state
const QuizCardSkeleton = () => (
  <div className="relative rounded-xl overflow-hidden bg-slate-800 animate-pulse">
    <div className="w-full aspect-[4/3] bg-slate-700" />
    <div className="absolute inset-0 p-6 flex flex-col justify-between">
      <div>
        <div className="h-8 w-3/4 bg-slate-600 rounded mb-2" />
        <div className="h-4 w-1/2 bg-slate-600 rounded" />
      </div>
      <div className="flex gap-2">
        <div className="h-6 w-20 bg-slate-600 rounded-full" />
        <div className="h-6 w-24 bg-slate-600 rounded-full" />
      </div>
    </div>
  </div>
);

// Icons
const ChevronLeftIcon = ({ className }: { className?: string }) => (
  <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
  </svg>
);

const ChevronRightIcon = ({ className }: { className?: string }) => (
  <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
  </svg>
);

const AlertIcon = ({ className }: { className?: string }) => (
  <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
);

const InboxIcon = ({ className }: { className?: string }) => (
  <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
  </svg>
);

export default function GetAllQuizzes({
  quizzes,
  loading,
  error,
  page,
  hasMore,
  searchQuery,
  onPrevious,
  onNext,
}: GetAllQuizzesProps) {
  const isSearching = searchQuery && searchQuery.trim().length > 0;

  // Loading skeletons
  if (loading) {
    return (
      <>
        {Array.from({ length: 6 }).map((_, i) => (
          <QuizCardSkeleton key={i} />
        ))}
      </>
    );
  }

  // Error state
  if (error) {
    return (
      <div className="col-span-full flex flex-col items-center justify-center py-16">
        <div className="w-16 h-16 bg-red-500/10 rounded-full flex items-center justify-center mb-4">
          <AlertIcon className="w-8 h-8 text-red-400" />
        </div>
        <h3 className="text-lg font-medium text-white mb-2">Une erreur est survenue</h3>
        <p className="text-gray-400 text-sm">{error}</p>
      </div>
    );
  }

  // Empty state
  if (!loading && quizzes.length === 0) {
    return (
      <div className="col-span-full flex flex-col items-center justify-center py-16">
        {isSearching ? (
          <>
            <div className="w-16 h-16 bg-slate-700/50 rounded-full flex items-center justify-center mb-4">
              <SearchXIcon className="w-8 h-8 text-gray-400" />
            </div>
            <h3 className="text-lg font-medium text-white mb-2">Aucun résultat</h3>
            <p className="text-gray-400 text-sm">
              Essayez avec d&apos;autres mots-clés ou vérifiez l&apos;orthographe
            </p>
          </>
        ) : (
          <>
            <div className="w-16 h-16 bg-slate-700/50 rounded-full flex items-center justify-center mb-4">
              <InboxIcon className="w-8 h-8 text-gray-400" />
            </div>
            <h3 className="text-lg font-medium text-white mb-2">Aucun quiz trouvé</h3>
            <p className="text-gray-400 text-sm">Soyez le premier à créer un quiz !</p>
          </>
        )}
      </div>
    );
  }

  return (
    <>
      {/* Quiz Cards */}
      {quizzes.map((quiz) => (
        <QuizCard key={quiz.id} quizData={quiz} />
      ))}

      {/* Pagination */}
      <div className="col-span-full flex items-center justify-center gap-3 mt-8">
        <button
          onClick={onPrevious}
          disabled={page <= 1}
          className="flex items-center gap-1 px-4 py-2.5 rounded-xl bg-slate-800/50 border border-slate-700/50 
                     text-white text-sm font-medium hover:bg-slate-700/50 hover:border-slate-600
                     disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-slate-800/50
                     transition-all duration-200"
        >
          <ChevronLeftIcon className="w-4 h-4" />
          Précédent
        </button>

        <div className="flex items-center gap-1 px-4 py-2 rounded-xl bg-slate-800/30 border border-slate-700/30">
          <span className="text-sm text-gray-400">Page</span>
          <span className="text-sm font-semibold text-white ml-1">{page}</span>
        </div>

        <button
          onClick={onNext}
          disabled={!hasMore}
          className="flex items-center gap-1 px-4 py-2.5 rounded-xl bg-slate-800/50 border border-slate-700/50 
                     text-white text-sm font-medium hover:bg-slate-700/50 hover:border-slate-600
                     disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-slate-800/50
                     transition-all duration-200"
        >
          Suivant
          <ChevronRightIcon className="w-4 h-4" />
        </button>
      </div>
    </>
  );
}
