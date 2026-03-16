using System.Security.Cryptography;

public class CsrfMiddleware
{
 private readonly RequestDelegate _next;
 private const string CsrfTokenCookieName = "XSRF-TOKEN";
 private const string CsrfTokenHeaderName = "X-CSRF-TOKEN";
 
 public CsrfMiddleware(RequestDelegate next)
 {
     _next = next;
}
 
 public async Task InvokeAsync(HttpContext context)
 {
    // Generate and set CSRF token for GET requests
     if (context.Request.Method == "GET")
     {
         // Generate token
         var token = context.Request.Cookies[CsrfTokenCookieName];
         if (string.IsNullOrEmpty(token))
         {
             token = GenerateToken();
             context.Response.Cookies.Append(CsrfTokenCookieName, token, new CookieOptions
             {
                 HttpOnly = false, // Allow JavaScript access
                 Secure = false, // Allow sending over HTTP for development (set to true in production)
                 SameSite = SameSiteMode.Strict, // Prevent CSRF attacks
                 Path = "/"
             });
         }
     }
    else if (context.Request.Method != "GET")
    {
        // Skip CSRF validation for API routes
        if (context.Request.Path.StartsWithSegments("/api"))
        {
            await _next(context);
            return;
        }
        var cookieToken = context.Request.Cookies[CsrfTokenCookieName];
        var headerToken = context.Request.Headers[CsrfTokenHeaderName].FirstOrDefault();
        
        if (string.IsNullOrEmpty(cookieToken) || string.IsNullOrEmpty(headerToken) || cookieToken != headerToken)
        {
            context.Response.StatusCode = 403;
            await context.Response.WriteAsJsonAsync(new { error = "CSRF token mismatch" });
            return;
        }
    }     

     await _next(context);
 }
    private static string GenerateToken()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    }
}