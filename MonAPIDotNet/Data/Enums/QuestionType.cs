using System.Text.Json.Serialization;

namespace MonAPIDotNet.Data
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum QuestionType
    {
        MultipleChoice,
        TrueFalse,
        ShortAnswer,
    }
}