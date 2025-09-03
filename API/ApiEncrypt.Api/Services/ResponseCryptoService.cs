using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ApiEncrypt.Api.Services;

public class ResponseCryptoService
{
    private readonly RSA _frontendPublicKey;

    public ResponseCryptoService(byte[] frontendPublicKeyBytes)
    {
        _frontendPublicKey = RSA.Create();
        _frontendPublicKey.ImportRSAPublicKey(frontendPublicKeyBytes, out _);
    }

    public EncryptedResponse EncryptResponse<T>(T responseData)
    {
        using var aes = Aes.Create();
        aes.GenerateKey();
        aes.GenerateIV();

        var plainBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(responseData));
        var encryptedData = aes.CreateEncryptor().TransformFinalBlock(plainBytes, 0, plainBytes.Length);

        var keyIv = aes.Key.Concat(aes.IV).ToArray();
        var encryptedKey = _frontendPublicKey.Encrypt(keyIv, RSAEncryptionPadding.OaepSHA256);

        return new EncryptedResponse
        {
            Key = Convert.ToBase64String(encryptedKey),
            Data = Convert.ToBase64String(encryptedData)
        };
    }
}

public class EncryptedResponse
{
    public string Key { get; set; }
    public string Data { get; set; }
}