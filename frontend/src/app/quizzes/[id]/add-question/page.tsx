"use client";

import CreateQuestion from "@/app/components/Question/CreateQuestion";
import { useParams } from "next/navigation";
import Link from "next/link";

export default function AddQuestion() {
    const params = useParams<{ id: string }>();

    return (
        <div>
            <h1>Ajouter une question</h1>
            <CreateQuestion quizId={params.id} />
            <Link href={`/quizzes/${params.id}`}>Terminer</Link>
        </div>
    );
}