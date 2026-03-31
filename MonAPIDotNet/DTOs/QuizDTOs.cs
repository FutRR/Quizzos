namespace MonAPIDotNet.DTOs
{
    public class QuizDTO
    {
        public int Id { get; set; }
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Difficulty { get; set; }
        public string? ImageUrl { get; set; } 
        public string AuthorId { get; set; }
        public string AuthorName { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
        public List<QuestionDTO> Questions { get; set; } = new List<QuestionDTO>();
        public List<int> TagIds { get; set; } = new List<int>();
        public List<TagDto> Tags { get; set; } = new List<TagDto>();
    }

    public class CreateQuizDTO
    {
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Difficulty { get; set; } = string.Empty;
        public string? ImageUrl { get; set; }
        public List<int> TagIds { get; set; } = new List<int>();
    }

    public class UpdateQuizDTO
    {
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Difficulty { get; set; } = string.Empty;
        public string? ImageUrl { get; set; }
        public List<int> TagIds { get; set; } = new List<int>();
        public List<QuestionDTO> Questions { get; set; } = new List<QuestionDTO>();
    }
}
