"use client";

import Link from "next/link";
import GetAllQuizzes from "../components/Quizz/GetAllQuizzes";

export default function Quizzes() {
  return (
    <div>
      <Link
        href="/quizzes/new"
        className="bg-blue-500 text-white rounded p-2 cursor-pointer hover:bg-blue-600 transition-colors mb-6 inline-block"
      >
        Créer un nouveau quiz
      </Link>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
        <GetAllQuizzes />
      </div>
    </div>
  );
}
