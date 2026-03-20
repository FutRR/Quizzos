using System.ComponentModel.DataAnnotations;

namespace MonAPIDotNet.DTOs
{
    public class TagDto
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string? Color { get; set; }
    }

    public class CreateTagDto
    {
        [Required]
        [StringLength(30, MinimumLength = 2)]
        public string Name { get; set; } = string.Empty;
        
        [StringLength(7)]
        public string? Color { get; set; }
    }

    public class UpdateTagDto
    {
        [StringLength(30, MinimumLength = 2)]
        public string? Name { get; set; }
        
        [StringLength(7)]
        public string? Color { get; set; }
    }
}