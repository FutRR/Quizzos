using System.ComponentModel.DataAnnotations;

namespace MonAPIDotNet.Data
{
    public enum PlayerRole
    {
        Civilian,
        Impostor
    }

    public class ImpostorPlayer
    {
        [Key]
        public int Id { get; set; }
        public Guid SessionId { get; set; }
        public string UserId { get; set; } = string.Empty;
        public PlayerRole Role { get; set; }
        public bool IsEliminated { get; set; } = false;
        public DateTime? EliminatedAt { get; set; }
        public DateTime JoinedAt { get; set; } = DateTime.UtcNow;
        public bool HasVoted { get; set; } = false;
        public int? VotedForPlayerId { get; set; }

        public virtual ImpostorGameSession Session { get; set; } = null!;
        public virtual ApplicationUser User { get; set; } = null!;
    }
}
