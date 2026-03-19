using System.ComponentModel.DataAnnotations;

namespace MonAPIDotNet.Data
{
    public class Quiz
    {
        [Key]
        public int Id { get; set; }
        
        [Required]
        [MaxLength(50)]
        public string Title { get; set; } = string.Empty;
        
        [MaxLength(500)]
        public string? Description { get; set; }
        
        [Required]
        public string AuthorId { get; set; }
        public ApplicationUser Author { get; set; }
        
        public DifficultyType Difficulty { get; set; }
        [MaxLength(255)]
        public string? ImageUrl { get; set; }
        
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        
        public DateTime? UpdatedAt { get; set; }
        
        // Relations many-to-many
        public ICollection<QuizTag> QuizTags { get; set; } = new List<QuizTag>();
        // Relations one-to-many
        public ICollection<Question> Questions { get; set; } = new List<Question>();
    }
}