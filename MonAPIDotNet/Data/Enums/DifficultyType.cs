using System.Text.Json.Serialization;

namespace MonAPIDotNet.Data
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum DifficultyType
    {
        Easy,
        Medium,
        Hard
    }
}