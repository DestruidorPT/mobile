using Newtonsoft.Json;

namespace Bit.Core.Models.Data
{
    /// <summary>
    /// Object contains the response data to the server
    /// </summary>
    public class Fido2AssertionResponse : Data
    {
        [JsonProperty("authenticatorData")]
        public string AuthenticatorData { get; set; } // the authenticator data in a byte array that contains metadata about the registration event (counter) and the server address;
        [JsonProperty("signature")]
        public string Signature { get; set; } //The signature created from the challenge using the private key
        [JsonProperty("clientDataJson")]
        public string ClientDataJson { get; set; } // contains the challenge, the origin, and type of operation
        [JsonProperty("userHandle")]
        public string UserHandle { get; set; } // This field is optionally provided by the authenticator and represents the user.id that was provided during the challenge request.
    }
}
