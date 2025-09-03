using System.Security.Cryptography;
using System.Text.Json;

namespace ApiEncrypt.Api;

public class EncryptionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly AppSettings _settings;

    public EncryptionMiddleware(RequestDelegate next, AppSettings settings)
    {
        _next = next;
        _settings = settings;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (_settings.EncryptionEnabled)
        {
            var requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();

            // Check if request contains 'encryptedData' field
            if (!requestBody.Contains("encryptedData"))
            {
                // Generate ephemeral RSA key pair
                using var rsa = RSA.Create(2048);
                var publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
                var privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());

                // Store private key in memory (for this session or temporary storage)
                context.Items["PrivateKey"] = privateKey;

                // Return public key to frontend
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonSerializer.Serialize(new
                {
                    encryptionRequired = true,
                    publicKey = publicKey
                }));
                return;
            }
        }

        await _next(context);
    }
}

