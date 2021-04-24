using Bit.Core.Models.Data;
using Newtonsoft.Json;

namespace Bit.Core.Models.Request
{
    /// <summary>
    /// Request to send to the server where contains the rensponse of the FIDO2 Client
    /// </summary>
    public class Fido2AuthenticationChallengeRequest
    {
        [JsonProperty("id")]
        public string Id { get; set; } // id of FIDO2 Key used
        [JsonProperty("rawId")]
        public string RawId { get; set; }  // id of FIDO2 Key used
        [JsonProperty("response")]
        public Fido2AssertionResponse Response { get; set; } // Response to the FIDO2 Server request
        [JsonProperty("type")]
        public string Type { get; set; } // type of algorithm used, public-key
        [JsonProperty("extensions", NullValueHandling = NullValueHandling.Ignore)]
        public string Extensions { get; set; } // Additional parameters used to ensure better security or other options
    }
}
