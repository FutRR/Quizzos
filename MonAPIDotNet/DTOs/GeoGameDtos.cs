namespace MonAPIDotNet.DTOs;

public record RoundDto(Guid RoundId, string ImageId);
public record GuessRequest(Guid RoundId, double Lat, double Lng);
public record GuessResultDto(double DistanceKm, int Score, double ActualLat, double ActualLng);