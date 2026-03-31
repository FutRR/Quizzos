"use client";
import { use } from "react";
import EditQuizz from "@/app/components/Quizz/EditQuizz";

export default function EditQuiz({params}: {params: Promise<{id: string}>}) {
    const { id } = use(params);

    return (
        <div>
            <EditQuizz quizId={id} />
        </div>
    );
}