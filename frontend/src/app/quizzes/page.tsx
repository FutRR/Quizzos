"use client";

import { useState } from "react";
import Link from "next/link";
import { useQuiz } from "../hooks/useQuiz";
import GetAllQuizzes from "../components/Quizz/GetAllQuizzes";

// Icons
const SparklesIcon = ({ className }: { className?: string }) => (
  <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M5 3v4M3 5h4M6 17v4m-2-2h4m5-16l2.286 6.857L21 12l-5.714 2.143L13 21l-2.286-6.857L5 12l5.714-2.143L13 3z" />
  </svg>
);

const PlusIcon = ({ className }: { className?: string }) => (
  <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
  </svg>
);

const SearchIcon = ({ className }: { className?: string }) => (
  <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
  </svg>
);

const XIcon = ({ className }: { className?: string }) => (
  <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
  </svg>
);

const PAGE_SIZE = 12;

export default function Quizzes() {
  const [searchValue, setSearchValue] = useState("");
  const {
    quizzes,
    loading,
    error,
    page,
    hasMore,
    searchQuery,
    debouncedSearch,
    searchQuizzes,
    getQuizzes,
  } = useQuiz();

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setSearchValue(value);
    debouncedSearch(value, 1, PAGE_SIZE);
  };

  const clearSearch = () => {
    setSearchValue("");
    getQuizzes(1, PAGE_SIZE);
  };

  const isSearching = searchValue.trim().length > 0;

  const handlePrevious = () => {
    if (page > 1) {
      if (searchQuery && searchQuery.trim()) {
        searchQuizzes(searchQuery, page - 1, PAGE_SIZE);
      } else {
        getQuizzes(page - 1, PAGE_SIZE);
      }
    }
  };

  const handleNext = () => {
    if (hasMore) {
      if (searchQuery && searchQuery.trim()) {
        searchQuizzes(searchQuery, page + 1, PAGE_SIZE);
      } else {
        getQuizzes(page + 1, PAGE_SIZE);
      }
    }
  };

  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <section className="relative overflow-hidden mb-8 rounded-3xl 
                          bg-gradient-to-br from-blue-600/20 via-purple-600/10 to-slate-900
                          border border-slate-700/50 p-8 md:p-12">
        {/* Decorative blobs */}
        <div className="absolute top-0 right-0 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl -translate-y-1/2 translate-x-1/2" />
        <div className="absolute bottom-0 left-0 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl translate-y-1/2 -translate-x-1/2" />

        <div className="relative z-10 max-w-3xl">

          <h1 className="text-4xl md:text-5xl font-bold text-white mb-4 leading-tight">
            Testez vos{" "}
            <span className="bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
              connaissances
            </span>
          </h1>

          <p className="text-lg text-gray-300 mb-6 max-w-2xl">
            Explorez et testez vos connaissances sur des milliers de sujets.
            Créez vos propres quiz et partagez-les avec la communauté !
          </p>

          <Link
            href="/quizzes/new"
            className="group inline-flex items-center gap-2 bg-gradient-to-r from-blue-500 to-blue-600 
                       text-white px-6 py-3 rounded-xl font-medium shadow-lg shadow-blue-500/20
                       hover:shadow-blue-500/40 hover:scale-[1.02] active:scale-[0.98]
                       transition-all duration-200"
          >
            <PlusIcon className="w-5 h-5 group-hover:rotate-90 transition-transform duration-200" />
            Créer un quiz
          </Link>
        </div>
      </section>

      {/* Search Section */}
      <div className="relative mb-8">
        {/* Search Bar */}
        <div className="relative max-w-md">
          <SearchIcon className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
          <input
            type="text"
            placeholder="Rechercher par titre, description ou tag..."
            value={searchValue}
            onChange={handleSearchChange}
            className="w-full bg-slate-800/50 border border-slate-700 rounded-xl py-3 pl-12 pr-10
                       text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50
                       focus:border-blue-500/50 transition-all"
          />
          {isSearching && (
            <button
              onClick={clearSearch}
              className="absolute right-3 top-1/2 -translate-y-1/2 p-1 rounded-full
                         text-gray-500 hover:text-white hover:bg-slate-700 transition-all"
            >
              <XIcon className="w-4 h-4" />
            </button>
          )}
        </div>
        
        {/* Search status indicator */}
        {isSearching && (
          <div className="mt-2 text-sm text-gray-400">
            Recherche: <span className="text-blue-400">&quot;{searchValue}&quot;</span>
          </div>
        )}
      </div>

      {/* Quiz Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
        <GetAllQuizzes
          quizzes={quizzes}
          loading={loading}
          error={error}
          page={page}
          hasMore={hasMore}
          searchQuery={searchQuery}
          onPrevious={handlePrevious}
          onNext={handleNext}
        />
      </div>
    </div>
  );
}
