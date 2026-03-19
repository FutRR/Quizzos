namespace MonAPIDotNet.DTOs
{
    public class QuestionDTO
    {
        public int Id { get; set; }
        public string Text { get; set; } = string.Empty;
        public QuestionType Type { get; set; }
        public int QuizId { get; set; }
        public List<string> Options { get; set; } = new List<string>();
        public string? CorrectAnswer { get; set; }
    }
}