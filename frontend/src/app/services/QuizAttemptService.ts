import fetchClient from "../lib/fetchClient";
import { SubmitQuizPayload, QuizAttemptResult, UserStats } from "../types/quizAttemptsType";

class QuizAttemptService {
  async submitQuiz(payload: SubmitQuizPayload): Promise<QuizAttemptResult> {
    return fetchClient.post<QuizAttemptResult>("/quizattempt/submit", payload);
  }
 
  async getUserStats(username: string): Promise<UserStats> {
    return fetchClient.get<UserStats>(`/quizattempt/stats/${username}`);
  }
}
 
export default new QuizAttemptService();