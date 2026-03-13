"use client";

import Link from "next/link";

export default function Quizzes() {
    return (
        <div>
            <h1>Quizzes</h1>
            <Link href="/quizzes/new" className="bg-blue-500 text-white rounded p-2 cursor-pointer hover:bg-blue-600 transition-colors">
                Créer un nouveau quiz
            </Link>
        </div>
    );
}