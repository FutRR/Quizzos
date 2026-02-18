namespace MonAPIDotNet.Models
{
    public record LoginRequest (string Username, string Password, string Audience);
    public record RefreshRequest (string Username,string Audience,string RefreshToken);
    public record RegisterRequest (string Username, string DisplayName, string Password);
}
