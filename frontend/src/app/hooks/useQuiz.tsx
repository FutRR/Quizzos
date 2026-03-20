import { useCallback, useState } from "react";
import { QuizService } from "../services/quizService";

export function useQuiz() {
    const [quizzes, setQuizzes] = useState<any[]>([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<any>(null);
    
    const quizService = new QuizService();
    
    const getQuizzes = async () => {
        setLoading(true);
        try {
            const response = await quizService.getQuizzes();
            setQuizzes(response);
        } catch (err) {
            setError(err as any);
        } finally {
            setLoading(false);
        }
    };

    const createQuiz = useCallback(async (data: any) => {
        try {
            setLoading(true);
            setError(null);
            const response = await quizService.createQuiz(data);
            setQuizzes([...quizzes, response]);
            return response;
        } catch (err) {
            setError(err as any);
            throw err;
        } finally {
            setLoading(false);
        }
    }, []);
    
    return {
        quizzes,
        loading,
        error,
        getQuizzes,
        createQuiz
    };
}