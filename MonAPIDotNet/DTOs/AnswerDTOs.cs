namespace MonAPIDotNet.DTOs
{
    public class AnswerDTO
    {
        public int Id { get; set; }
        public string Value { get; set; } = string.Empty;
        public bool IsCorrect { get; set; }
        public int QuestionId { get; set; }
    }
}