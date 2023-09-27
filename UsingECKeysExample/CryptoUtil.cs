using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto.Generators;

namespace UsingECKeysExample;

public static class CryptoUtil
{
    public static void GenerateKeys(string privateFilePath, string publicFilePath)
    {
        var keyGenerationParameters = new ECKeyGenerationParameters(
            SecNamedCurves.GetOid("secp256k1"),
            new SecureRandom());

        var generator = new ECKeyPairGenerator("ECDSA");
        generator.Init(keyGenerationParameters);

        var keyPair = generator.GenerateKeyPair();

        var privateKey = keyPair.Private as ECPrivateKeyParameters;
        var keyStructure = new ECPrivateKeyStructure(
            privateKey.Parameters.Curve.Order.BitLength,
            privateKey.D,
            null,
            privateKey.PublicKeyParamSet);

        byte[] serializedPrivateBytes = keyStructure.GetDerEncoded();
        File.WriteAllBytes(privateFilePath, serializedPrivateBytes);

        var publicKey = keyPair.Public as ECPublicKeyParameters;
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
        byte[] serializedPublicBytes = publicKeyInfo.GetDerEncoded();
        File.WriteAllBytes(publicFilePath, serializedPublicBytes);
    }

    public static ECPrivateKeyParameters LoadKey(string privateKeyFilePath) {
        return LoadKey(File.ReadAllBytes(privateKeyFilePath));
    }
    public static ECPrivateKeyParameters LoadKey(byte[] privateKeyBytes) {
        var asn1Obj = Asn1Object.FromByteArray(privateKeyBytes);
        var ecPrivateKeyStructure = ECPrivateKeyStructure.GetInstance(asn1Obj);
        var algId = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, ecPrivateKeyStructure.GetParameters());
        var privateKeyInfo = new PrivateKeyInfo(algId, ecPrivateKeyStructure.ToAsn1Object()); ;
        return (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(privateKeyInfo);
    }

    public static string Sign(String data, ECPrivateKeyParameters privateKey) {
        return Sign(Encoding.UTF8.GetBytes(data), privateKey);
    }
    public static string Sign(byte[] data, ECPrivateKeyParameters privateKey) {
        ISigner signer = SignerUtilities.GetSigner("SHA-256withECDSA");
        signer.Init(true, privateKey);
        signer.BlockUpdate(data, 0, data.Length);
        byte[] signature = signer.GenerateSignature();
        return Convert.ToBase64String(signature);
    }
}
