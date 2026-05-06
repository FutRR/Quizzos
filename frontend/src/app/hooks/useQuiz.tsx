import { useCallback, useState, useEffect, useRef } from "react";
import { QuizService } from "../services/quizService";

// Instance unique partagée (évite la recréation à chaque render)
const quizService = new QuizService();

export function useQuiz() {
  const [quizzes, setQuizzes] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");

  const searchTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const getQuizzes = useCallback(async (p: number = 1, pageSize: number = 12) => {
    setLoading(true);
    setError(null);
    try {
      const response = await quizService.getQuizzes(p, pageSize);
      setQuizzes(response);
      setPage(p);
      setHasMore(response.length >= pageSize);
      setSearchQuery("");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  const searchQuizzes = useCallback(async (query: string, p: number = 1, pageSize: number = 12) => {
    if (!query.trim()) {
      getQuizzes(p, pageSize);
      return;
    }

    setLoading(true);
    setError(null);
    setSearchQuery(query);
    try {
      const response = await quizService.searchQuizzes(query, p, pageSize);
      setQuizzes(response);
      setPage(p);
      setHasMore(response.length >= pageSize);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [getQuizzes]);

  // Debounced search function
  const debouncedSearch = useCallback((query: string, p: number = 1, pageSize: number = 12) => {
    if (searchTimeoutRef.current) {
      clearTimeout(searchTimeoutRef.current);
    }
    
    searchTimeoutRef.current = setTimeout(() => {
      searchQuizzes(query, p, pageSize);
    }, 300); // 300ms debounce
  }, [searchQuizzes]);

  useEffect(() => {
    getQuizzes(1);
    
    return () => {
      if (searchTimeoutRef.current) {
        clearTimeout(searchTimeoutRef.current);
      }
    };
  }, [getQuizzes]);

  const updateQuiz = useCallback(async (id: string, data: any) => {
    try {
      setLoading(true);
      setError(null);
      const response = await quizService.updateQuiz(id, data);
      setQuizzes((prev) => prev.map((q) => (q.id === id ? response : q)));
      return response;
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  const createQuiz = useCallback(async (data: any) => {
    try {
      setLoading(true);
      setError(null);
      const response = await quizService.createQuiz(data);
      setQuizzes((prev) => [...prev, response]);
      return response;
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  const getQuizById = useCallback(async (id: string) => {
    setLoading(true);
    setError(null);
    try {
      return await quizService.getQuizById(id);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  const getQuizzesByAuthorName = useCallback(async (authorName: string) => {
    setLoading(true);
    setError(null);
    try {
      return await quizService.getQuizzesByAuthorName(authorName);
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
      setQuizzes((prev) => prev.filter((q) => q.id !== id));
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
    searchQuery,
    getQuizzes,
    searchQuizzes,
    debouncedSearch,
    createQuiz,
    getQuizById,
    getQuizzesByAuthorName,
    updateQuiz,
    deleteQuiz,
  };
}
