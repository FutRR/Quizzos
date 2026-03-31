import questionService from "../services/questionService";

export function useQuestion() {
    const createQuestion = async (quizId: string, data: any) => {
        return await questionService.createQuestion(quizId, data);
    };
    
    const getQuestions = async (quizId: string) => {
        return await questionService.getQuestions(quizId);
    };
    
    const deleteQuestion = async (quizId: string, questionId: number) => {
        return await questionService.deleteQuestion(quizId, questionId);
    };
    
    return {
        createQuestion,
        getQuestions,
        deleteQuestion
    };
}
