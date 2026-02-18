namespace MonAPIDotNet.Data
{
    public class RefreshToken
    {
        public int Id { get; set; }
        public string Token { get; set; }
        public string Username { get; set; }
        public DateTime Expires { get; set; }
        public bool IsRevoked { get; set; }
        public bool IsExpired => DateTime.UtcNow >= Expires;
    }
}
