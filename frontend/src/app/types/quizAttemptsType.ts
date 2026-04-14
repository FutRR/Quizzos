export interface SubmitAnswerPayload {
  questionId: number;
  selectedOptionIds: number[];
}
 
export interface SubmitQuizPayload {
  quizId: number;
  answers: SubmitAnswerPayload[];
}
 
export interface QuestionResult {
  questionId: number;
  isCorrect: boolean;
  correctAnswerIds: number[];
  selectedAnswerIds: number[];
}
 
export interface QuizAttemptResult {
  attemptId: number;
  quizId: number;
  correctAnswers: number;
  totalQuestions: number;
  scorePercent: number;
  isFirstAttempt: boolean;
  isNewBestScore: boolean;
  results: QuestionResult[];
}
 
export interface UserStats {
  quizzesPlayed: number;
  totalAttempts: number;
  averageBestScorePercent: number;
  firstAttemptAverage: number | null;
}