using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MonAPIDotNet.DTOs;
using MonAPIDotNet.Service;

namespace MonAPIDotNet.Controllers;

[ApiController]
[Route("api/geogame")]
[Authorize]
public class GeoGameController : ControllerBase
{
    private readonly GeoGameService _service;

    public GeoGameController(GeoGameService service) => _service = service;

    [HttpPost("round")]
    public async Task<ActionResult<RoundDto>> CreateRound(CancellationToken ct)
        => Ok(await _service.CreateRoundAsync(ct));

    [HttpPost("guess")]
    public ActionResult<GuessResultDto> SubmitGuess([FromBody] GuessRequest req)
    {
        try { return Ok(_service.SubmitGuess(req.RoundId, req.Lat, req.Lng)); }
        catch (KeyNotFoundException) { return NotFound(); }
    }
}