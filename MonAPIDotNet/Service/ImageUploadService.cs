using CloudinaryDotNet;
using CloudinaryDotNet.Actions;
using Microsoft.Extensions.Logging;

namespace MonAPIDotNet.Service
{
    public interface IImageUploadService
    {
        Task<string> UploadImageAsync(IFormFile file);
    }

    public class CloudinaryImageUploadService : IImageUploadService
    {
    
    private readonly Cloudinary _cloudinary;
    private readonly ILogger<CloudinaryImageUploadService> _logger;

        public CloudinaryImageUploadService(IConfiguration config, ILogger<CloudinaryImageUploadService> logger)
        {
            var account = new Account(
                config["Cloudinary:CloudName"],
                config["Cloudinary:ApiKey"],
                config["Cloudinary:ApiSecret"]
            );
            _cloudinary = new Cloudinary(account);
            _logger = logger;
        }

        public async Task<string> UploadImageAsync(IFormFile file)
        {
            // Validation
            if (file.Length > 5 * 1024 * 1024) // 5MB max
                throw new ArgumentException("File size exceeds 5MB");

            var allowedTypes = new[] { "image/jpeg", "image/png", "image/gif", "image/webp" };
            if (!allowedTypes.Contains(file.ContentType))
                throw new ArgumentException("Invalid file type");

            // Upload vers Cloudinary
            using var stream = file.OpenReadStream();
            var uploadParams = new ImageUploadParams
            {
                File = new FileDescription(file.FileName, stream),
                Folder = "quiz-images",
                Format = "webp",
                Transformation = new Transformation()
                    .Width(800)
                    .Height(600)
                    .Crop("limit")
                    .Quality("auto:good")
                    .FetchFormat("auto")
            };

            var result = await _cloudinary.UploadAsync(uploadParams);
            
            if (result.Error != null)
            {
                _logger.LogError($"Cloudinary upload error: {result.Error.Message}");
                throw new Exception("Image upload failed");
            }

            return result.SecureUrl.ToString();
        }
    }
}