using System.Text.Json;
using Microsoft.EntityFrameworkCore;

namespace MonAPIDotNet.Data.Seed
{
    public static class ImpostorWordPairSeeder
    {
        private const string SeedRelativePath = "Data/Seed/impostor-wordpairs.json";

        public static async Task SeedAsync(IServiceProvider services, ILogger logger)
        {
            using var scope = services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<MyDbContext>();

            if (await db.ImpostorWordPairs.AnyAsync())
            {
                return;
            }

            var path = Path.Combine(AppContext.BaseDirectory, SeedRelativePath);
            if (!File.Exists(path))
            {
                logger.LogWarning("Impostor word pair seed file not found at {Path}", path);
                return;
            }

            var json = await File.ReadAllTextAsync(path);
            var pairs = JsonSerializer.Deserialize<List<ImpostorWordPair>>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            if (pairs is null || pairs.Count == 0)
            {
                logger.LogWarning("Impostor word pair seed file is empty: {Path}", path);
                return;
            }

            db.ImpostorWordPairs.AddRange(pairs);
            await db.SaveChangesAsync();

            logger.LogInformation("Seeded {Count} impostor word pairs from {Path}", pairs.Count, path);
        }
    }
}
