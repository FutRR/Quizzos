using System.ComponentModel.DataAnnotations;

namespace MonAPIDotNet.Data
{
    public class Answer
    {
        public int Id { get; set; }
        [Required]
        [MaxLength(50)]
        public string Value { get; set; } = string.Empty;
        public bool IsCorrect { get; set; }
        public int QuestionId { get; set; }
        public Question Question { get; set; }
    }
}