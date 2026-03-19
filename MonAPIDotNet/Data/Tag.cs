namespace MonAPIDotNet.Data
{
    public class Tag
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string? Color { get; set; }
        public DateTime CreatedAt { get; set; }

        // Relations many-to-many
        public ICollection<QuizTag> QuizTags { get; set; } = new List<QuizTag>();
    }
}
