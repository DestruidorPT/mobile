using Bit.Core.Models.Data;
using Newtonsoft.Json;
using System.Collections.Generic;

namespace Bit.Core.Models.Response
{
    /// <summary>
    /// Response from the server, where contains the data to be sign
    /// </summary>
    public class Fido2AuthenticationChallengeResponse
    {
        [JsonProperty("challenge")]
        public string Challenge { get; set; } // challenge to be sign
        [JsonProperty("rpId")]
        public string RpId { get; set; } // id of the server
        [JsonProperty("timeout")]
        public double Timeout { get; set; } // time limit to use this data
        [JsonProperty("allowCredentials")]
        public List<Fido2CredentialDescriptor> AllowCredentials { get; set; } // FIDO2 Keys that are alowed by the user to sign this challenge
        [JsonProperty("userVerification")]
        public string UserVerification { get; set; } // tell if the FIDO2 CLient should confirm with the user the operation before using FIDO2
        [JsonProperty("extensions", NullValueHandling = NullValueHandling.Ignore)]
        public object Extensions { get; set; } // Additional parameters used to ensure better security or other options
    }
}
