import { useCallback, useState, useEffect } from "react";
import { QuizService } from "../services/quizService";

export function useQuiz() {
  const [quizzes, setQuizzes] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(true);

  const quizService = new QuizService();

  const getQuizzes = useCallback(async (p: number = 1, pageSize: number = 12) => {
    setLoading(true);
    try {
      const response = await quizService.getQuizzes(p, pageSize);
      setQuizzes(response);
      setPage(p);
      setHasMore(response.length >= pageSize);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    getQuizzes(1);
  }, [getQuizzes]);

  // Add after getQuizzesByAuthorName (around line 71), before the return:

  const updateQuiz = useCallback(
    async (id: string, data: any) => {
      try {
        setLoading(true);
        setError(null);
        const response = await quizService.updateQuiz(id, data);
        setQuizzes(quizzes.map((q) => (q.id === id ? response : q)));
        return response;
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [quizzes],
  );

  const createQuiz = useCallback(
    async (data: any) => {
      try {
        setLoading(true);
        setError(null);
        const response = await quizService.createQuiz(data);
        setQuizzes([...quizzes, response]);
        return response;
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [quizzes],
  );

  const getQuizById = useCallback(async (id: string) => {
    try {
      setLoading(true);
      setError(null);
      const response = await quizService.getQuizById(id);
      return response;
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  const getQuizzesByAuthorName = useCallback(async (authorName: string) => {
    try {
      setLoading(true);
      setError(null);
      const response = await quizService.getQuizzesByAuthorName(authorName);
      return response;
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  const deleteQuiz = useCallback(async (id: string) => {
    try {
      setLoading(true);
      setError(null);
      await quizService.deleteQuiz(id);
      setQuizzes(quizzes.filter((q) => q.id !== id));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  return {
    quizzes,
    loading,
    error,
    page,
    hasMore,
    getQuizzes,
    createQuiz,
    getQuizById,
    getQuizzesByAuthorName,
    updateQuiz,
    deleteQuiz,
  };
}
