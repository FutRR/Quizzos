using Microsoft.Extensions.Caching.Memory;
using MonAPIDotNet.DTOs;

namespace MonAPIDotNet.Service;

public class GeoGameService
{
    // Liste d'IDs Mapillary pré-curés (à remplacer par de vrais IDs).
    // Pour récupérer un ID : https://www.mapillary.com/app/ → clique sur une photo → Image details → Image ID.
    private static readonly string[] ImagePool = new[]
    {
        "806967170244200",   // Tuileries, Paris
        "3073251589649942", // Atheneum, Liège
        "215254963455635", // Promenade des Bastions, Genève
        "1068239820447414", // Parc ? , Moscou
        "303781798431560" // Parc Hibaya, Tokyo
    };

    private readonly MapillaryService _mapillary;
    private readonly IMemoryCache _cache;
    private static readonly Random Rng = new();

    public GeoGameService(MapillaryService mapillary, IMemoryCache cache)
    {
        _mapillary = mapillary;
        _cache = cache;
    }

    public async Task<RoundDto> CreateRoundAsync(CancellationToken ct)
    {
        var id = ImagePool[Rng.Next(ImagePool.Length)];
        var (lat, lng) = await _mapillary.GetImageLocationAsync(id, ct);
        var roundId = Guid.NewGuid();
        _cache.Set(CacheKey(roundId), (lat, lng), TimeSpan.FromMinutes(10));
        return new RoundDto(roundId, id);
    }

    public GuessResultDto SubmitGuess(Guid roundId, double lat, double lng)
    {
        if (!_cache.TryGetValue<(double Lat, double Lng)>(CacheKey(roundId), out var actual))
            throw new KeyNotFoundException("Round expired or unknown.");

        _cache.Remove(CacheKey(roundId));
        var dist = Haversine(lat, lng, actual.Lat, actual.Lng);
        var score = (int)Math.Round(5000 * Math.Exp(-dist / 2000.0));
        return new GuessResultDto(dist, score, actual.Lat, actual.Lng);
    }

    private static string CacheKey(Guid id) => $"geogame:round:{id}";

    private static double Haversine(double lat1, double lng1, double lat2, double lng2)
    {
        const double R = 6371.0; // km
        double ToRad(double d) => d * Math.PI / 180.0;
        var dLat = ToRad(lat2 - lat1);
        var dLng = ToRad(lng2 - lng1);
        var a = Math.Sin(dLat / 2) * Math.Sin(dLat / 2) +
                Math.Cos(ToRad(lat1)) * Math.Cos(ToRad(lat2)) *
                Math.Sin(dLng / 2) * Math.Sin(dLng / 2);
        return 2 * R * Math.Asin(Math.Sqrt(a));
    }
}
