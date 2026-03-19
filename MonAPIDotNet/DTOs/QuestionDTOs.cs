namespace MonAPIDotNet.DTOs
{
    public class QuestionDTO
    {
        public int Id { get; set; }
        public string Text { get; set; } = string.Empty;
        public bool IsTimed { get; set; }
        public int? TimeLimit { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
        public string Type { get; set; }
        public int QuizId { get; set; }
        public List<string> ImagesUrls { get; set; } = new List<string>();
        public List<AnswerDTO> Answers { get; set; } = new List<AnswerDTO>();
    }
}