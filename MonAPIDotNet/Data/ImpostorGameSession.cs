using System.ComponentModel.DataAnnotations;

namespace MonAPIDotNet.Data
{
    public enum GameStatus
    {
        Waiting,
        InProgress,
        Finished
    }

    public enum WinnerType
    {
        None,
        Civilians,
        Impostor
    }

    public class ImpostorGameSession
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();
        [Required]
        [StringLength(6)]
        public string Code { get; set; } = string.Empty;
        public GameStatus Status { get; set; } = GameStatus.Waiting;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public string? SecretWord { get; set; }
        public string? ImpostorWord { get; set; }
        public WinnerType Winner { get; set; } = WinnerType.None;
        public virtual ICollection<ImpostorPlayer> Players { get; set; } = new List<ImpostorPlayer>();
    }
}
