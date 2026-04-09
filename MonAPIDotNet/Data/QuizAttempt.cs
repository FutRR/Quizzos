using System.ComponentModel.DataAnnotations;

namespace MonAPIDotNet.Data
{
    public class QuizAttempt
    {
        [Key]
        public int Id { get; set; }
        
        [Required]
        public string UserId { get; set; }
        public ApplicationUser User { get; set; }
        
        [Required]
        public int QuizId { get; set; }
        public Quiz Quiz { get; set; }
        
        public int CorrectAnswers { get; set; }
        public int TotalQuestions { get; set; }
        public double ScorePercentage { get; set; }
        
        public DateTime CompletedAt { get; set; } = DateTime.UtcNow;
        
        public bool IsFirstAttempt { get; set; }
    }
}