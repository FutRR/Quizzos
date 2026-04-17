using MonAPIDotNet.Data;

namespace MonAPIDotNet.DTOs
{
    public class PlayerWordDto
    {
        public PlayerRole Role { get; set; }
        public string Word { get; set; } = string.Empty;
    }

    public class VoteSubmissionDto
    {
        public int TargetPlayerId { get; set; }
    }

    public class GameSessionInfoDto
    {
        public Guid Id { get; set; }
        public string Code { get; set; } = string.Empty;
        public GameStatus Status { get; set; }
        public int PlayerCount { get; set; }
    }
}
