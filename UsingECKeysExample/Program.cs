// See https://aka.ms/new-console-template for more information
using UsingECKeysExample;

string json = @"{
  ""key1"": ""Key one"",
  ""key2"": ""Key two""
}";


CryptoUtil.GenerateKeys("../../../keys/ecPrivateKey.der", "../../../keys/ecPublicKey.der");
var privateKey2 = CryptoUtil.LoadKey("../../../keys/ecPrivateKey.der");

var signature = CryptoUtil.Sign(JsonUtil.Normalize(json), privateKey2);
Console.WriteLine($"Base64 Encoded Signature: {signature}");


