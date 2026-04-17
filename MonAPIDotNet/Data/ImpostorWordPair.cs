using System.ComponentModel.DataAnnotations;

namespace MonAPIDotNet.Data
{
    public class ImpostorWordPair
    {
        [Key]
        public int Id { get; set; }
        [Required]
        public string WordA { get; set; } = string.Empty;
        [Required]
        public string WordB { get; set; } = string.Empty;
        public string? Category { get; set; }
    }
}
