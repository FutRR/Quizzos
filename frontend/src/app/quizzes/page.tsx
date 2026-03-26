"use client";

import Link from "next/link";
import GetAllQuizzes from "../components/Quizz/GetAllQuizzes";

export default function Quizzes() {
    return (
        <div>
            <Link href="/quizzes/new" className="bg-blue-500 text-white rounded p-2 cursor-pointer hover:bg-blue-600 transition-colors">
                Créer un nouveau quiz
            </Link>
            <GetAllQuizzes />
        </div>
    );
}