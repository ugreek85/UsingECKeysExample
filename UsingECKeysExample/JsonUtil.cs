using System.Text.Json;

namespace UsingECKeysExample;

public static class JsonUtil
{
    public static String Normalize(string json) {
        using JsonDocument doc = JsonDocument.Parse(json);
        return JsonSerializer.Serialize(doc.RootElement);
    }
}
