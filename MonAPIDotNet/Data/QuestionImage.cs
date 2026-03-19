namespace MonAPIDotNet.Data
{
    public class QuestionImage
    {
        public int Id { get; set; }
        public string Url { get; set; } = string.Empty;
        public int Order { get; set; }
        public int QuestionId { get; set; }
        public Question Question { get; set; }
    }
}