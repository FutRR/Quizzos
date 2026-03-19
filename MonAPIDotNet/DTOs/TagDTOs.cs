namespace MonAPIDotNet.DTOs
{
    public class TagDTO
    {
        public int Id { get; set; }
        public string Name { get; set; } = null!;
        public string? Color { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}