import fetchClient from "../lib/fetchClient";

export interface AnswerPayload {
  value: string;
  isCorrect: boolean;
}

export interface CreateQuestionPayload {
  text: string;
  type: string;
  isTimed: boolean;
  timeLimit?: number;
  imagesUrls: string[];
  answers: AnswerPayload[];
}

export interface QuestionDTO {
  id: number;
  text: string;
  type: string;
  isTimed: boolean;
  timeLimit?: number;
  quizId: number;
  imagesUrls: string[];
  answers: {
    id: number;
    value: string;
    isCorrect: boolean;
    questionId: number;
  }[];
  createdAt: string;
  updatedAt?: string;
}

class QuestionService {
  async createQuestion(quizId: string, data: CreateQuestionPayload): Promise<QuestionDTO> {
    return fetchClient.post<QuestionDTO>(`/quiz/${quizId}/questions`, data);
  }

  async getQuestions(quizId: string): Promise<QuestionDTO[]> {
    return fetchClient.get<QuestionDTO[]>(`/quiz/${quizId}/questions`);
  }

  async deleteQuestion(quizId: string, questionId: number): Promise<void> {
    return fetchClient.delete(`/quiz/${quizId}/questions/${questionId}`);
  }
}

export default new QuestionService();
