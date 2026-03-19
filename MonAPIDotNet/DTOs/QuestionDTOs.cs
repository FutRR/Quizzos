namespace MonAPIDotNet.DTOs
{
    public class QuestionDTO
    {
        public int Id { get; set; }
        public string Text { get; set; } = string.Empty;
        public string Type { get; set; }
        public int QuizId { get; set; }
    }
}