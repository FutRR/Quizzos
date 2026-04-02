import fetchClient from "../lib/fetchClient";

export class QuizService {
    // Get all quizzes
    async getQuizzes(page: number = 1, pageSize: number = 12): Promise<any> {
        const response = await fetchClient.get(`/quiz/quizzes?page=${page}&pageSize=${pageSize}`);
        return response;
    }
    // Get quiz by ID
    async getQuizById(id: string): Promise<any> {
        const response = await fetchClient.get(`/quiz/${id}`);
        return response;
    }
    // Get quizzes by author name
    async getQuizzesByAuthorName(authorName: string): Promise<any> {
        const response = await fetchClient.get(`/quiz/${authorName}/quizzes`);
        return response;
    }
    // Create quiz
    async createQuiz(data: any): Promise<any> {
        const response = await fetchClient.post("/quiz/new", data);
        return response;
    }
    // Update quiz
    async updateQuiz(id: string, data: any): Promise<any> {
        const response = await fetchClient.patch(`/quiz/${id}`, data);
        return response;
    }
    // Delete quiz
    async deleteQuiz(id: string): Promise<any> {
        const response = await fetchClient.delete(`/quiz/${id}`);
        return response;
    }
}
