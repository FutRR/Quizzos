"use client";

import Link from "next/link";

export default function Quizzes() {
    return (
        <div>
            <Link href="/quizzes/new" className="bg-blue-500 text-white rounded p-2 cursor-pointer hover:bg-blue-600 transition-colors">
                Créer un nouveau quiz
            </Link>
            <p className="text-center text-gray-500 text-sm">Quizz</p>
        </div>
    );
}