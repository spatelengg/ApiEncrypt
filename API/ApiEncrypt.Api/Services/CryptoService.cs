using System.Security.Cryptography;
using System.Text;

namespace ApiEncrypt.Api.Services;
  
public class CryptoService
{
    private readonly RSA _privateKey;

    public CryptoService(byte[] privateKeyBytes)
    {
        _privateKey = RSA.Create();
        _privateKey.ImportRSAPrivateKey(privateKeyBytes, out _);
    }

    public string Decrypt(string base64Cipher)
    {
        var cipherBytes = Convert.FromBase64String(base64Cipher);
        var decryptedBytes = _privateKey.Decrypt(cipherBytes, RSAEncryptionPadding.OaepSHA256);
        return Encoding.UTF8.GetString(decryptedBytes);
    }
}
