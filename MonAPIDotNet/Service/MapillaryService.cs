using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Configuration;

namespace MonAPIDotNet.Service;

public class MapillaryImage
{
    public string Id { get; set; } = "";
    public double Lat { get; set; }
    public double Lng { get; set; }
}

public class MapillaryService
{
    private readonly HttpClient _http;
    private readonly string _token;

    public MapillaryService(HttpClient http, IConfiguration config)
    {
        _http = http;
        _token = config["Mapillary:ClientToken"]
                 ?? throw new InvalidOperationException("Missing Mapillary:ClientToken");
    }

    public async Task<(double Lat, double Lng)> GetImageLocationAsync(string id, CancellationToken ct = default)
    {
        var url = $"https://graph.mapillary.com/{id}" +
                  $"?access_token={_token}" +
                  $"&fields=geometry,computed_geometry";

        using var resp = await _http.GetAsync(url, ct);
        if (!resp.IsSuccessStatusCode)
        {
            var body = await resp.Content.ReadAsStringAsync(ct);
            throw new HttpRequestException(
                $"Mapillary API {(int)resp.StatusCode} {resp.StatusCode}: {body}");
        }
        using var stream = await resp.Content.ReadAsStreamAsync(ct);
        using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
        var root = doc.RootElement;

        JsonElement geom;
        if (!root.TryGetProperty("computed_geometry", out geom) &&
            !root.TryGetProperty("geometry", out geom))
            throw new InvalidOperationException($"No geometry found for image {id}");

        var coords = geom.GetProperty("coordinates");
        return (coords[1].GetDouble(), coords[0].GetDouble());
    }
}