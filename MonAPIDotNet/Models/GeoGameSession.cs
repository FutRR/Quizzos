namespace MonAPIDotNet.Models;

public class GeoGameSession
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public DateTime StartedAt { get; set; }
    public DateTime? FinishedAt { get; set; }
    public int TotalScore { get; set; }
    public List<GeoGameRound> Rounds { get; set; } = new();
}

public class GeoGameRound
{
    public int Id { get; set; }
    public int SessionId { get; set; }
    public int Index { get; set; }
    public string ImageId { get; set; } = "";
    public double ActualLat { get; set; }
    public double ActualLng { get; set; }
    public double? GuessLat { get; set; }
    public double? GuessLng { get; set; }
    public double? DistanceKm { get; set; }
    public int? Score { get; set; }
}