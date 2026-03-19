using System.ComponentModel.DataAnnotations;

namespace MonAPIDotNet.Data
{
    public class Question
    {
        public int Id { get; set; }
        [MaxLength(200)]
        public string Text { get; set; } = string.Empty;
        public ICollection<QuestionImage> Images { get; set; } = new List<QuestionImage>();
        public bool IsTimed { get; set; }
        [Range(3, 300)]
        public int TimeLimit { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? UpdatedAt { get; set; }
        public QuestionType Type { get; set; }
        public ICollection<Answer> Answers { get; set; } = new List<Answer>();
    }
}