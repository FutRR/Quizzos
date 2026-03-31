"use client"

import { useQuestion } from "../../hooks/useQuestion";
import { useState } from "react";

export default function QuestionList({ quizId }: { quizId: string }) {
    const { getQuestions } = useQuestion();
    const [questions, setQuestions] = useState<any[]>([]);
    
    return (
        <div>
            {questions.map((question) => (
                <div key={question.id}>
                    <h1>{question.text}</h1>
                </div>
            ))}
        </div>
    )
}
