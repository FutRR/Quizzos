namespace MonAPIDotNet.Data
{
    public class AuthorizedApplication
    {
        public int Id { get; set; }
        public required string Audience { get; set; }
    }
}
