using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MonAPIDotNet.Service;

namespace MonAPIDotNet.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class UploadController : ControllerBase
    {
    private readonly IImageUploadService _imageUploadService;

    public UploadController(IImageUploadService imageUploadService)
    {
        _imageUploadService = imageUploadService;
    }

    [HttpPost("image")]
    [ProducesResponseType(typeof(ImageUploadResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<ImageUploadResponse>> UploadImage(IFormFile file)
    {
        if (file == null || file.Length == 0)
            return BadRequest("No file provided");

        try
        {
            var imageUrl = await _imageUploadService.UploadImageAsync(file);
            return Ok(new ImageUploadResponse { ImageUrl = imageUrl });
        }
        catch (ArgumentException ex)
        {
            return BadRequest(ex.Message);
        }
        catch (Exception ex)
        {
            return StatusCode(500, "An error occurred while uploading the image");
        }
    }
    }

    public class ImageUploadResponse
    {
        public string ImageUrl { get; set; }
    }
}
