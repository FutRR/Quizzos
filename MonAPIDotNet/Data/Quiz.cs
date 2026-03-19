using System.ComponentModel.DataAnnotations;

namespace MonAPIDotNet.Data
{
    public class Quiz
    {
        [Key]
        public int Id { get; set; }
        
        [Required]
        [MaxLength(200)]
        public string Title { get; set; } = string.Empty;
        
        [MaxLength(1000)]
        public string? Description { get; set; }
        
        [Required]
        public string AuthorId { get; set; }
        public ApplicationUser Author { get; set; }
        
        public DifficultyType Difficulty { get; set; }
        
        public string? ImageUrl { get; set; }
        
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        
        public DateTime? UpdatedAt { get; set; }
        
        // Relations many-to-many
        public ICollection<QuizTag> QuizTags { get; set; } = new List<QuizTag>();
    }
}