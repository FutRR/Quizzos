using System.ComponentModel.DataAnnotations;

namespace MonAPIDotNet.DTOs
{
    public class SubmitQuizDTO
    {
        [Required]
        public int QuizId { get; set; }
        [Required]
        public List<SubmitAnswerDTO> Answers { get; set; } = new();
    }

    public class SubmitAnswerDTO
    {
        public int QuestionId { get; set; }
        public List<int> SelectedOptionIds { get; set; } = new();
    }

    public class QuizAttemptResultDTO
    {
        public int AttemptId { get; set; }
        public int QuizId { get; set; }
        public int CorrectAnswers { get; set; }
        public int TotalQuestions { get; set; }
        public double ScorePercent { get; set; }
        public bool IsFirstAttempt { get; set; }
        public bool IsNewBestScore { get; set; }
    
        // Détail par question
        public List<QuestionResultDTO> Results { get; set; } = new();
    }

    public class QuestionResultDTO
    {
        public int QuestionId { get; set; }
        public bool IsCorrect { get; set; }
        public List<int> CorrectAnswerIds { get; set; } = new();
        public List<int> SelectedAnswerIds { get; set; } = new();
    }

}
