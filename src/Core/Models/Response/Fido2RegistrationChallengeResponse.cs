using Bit.Core.Models.Data;
using Newtonsoft.Json;
using System.Collections.Generic;

namespace Bit.Core.Models.Response
{
    /// <summary>
    /// Response from the server, where contains the data to be sign
    /// </summary>
    public class Fido2RegistrationChallengeResponse
    {
        [JsonProperty("challenge")]
        public string Challenge { get; set; } // challenge to be sign
        [JsonProperty("timeout")]
        public double Timeout { get; set; } // time limit to use this data
        [JsonProperty("rp")]
        public Fido2RP Rp { get; set; } // id of the server
        [JsonProperty("user")]
        public Fido2User User { get; set; } // id of the server
        [JsonProperty("pubKeyCredParams")]
        public List<Fido2PubKeyCredParam> PubKeyCredParams { get; set; } // id of the server
        [JsonProperty("excludeCredentials")]
        public List<Fido2CredentialDescriptor> ExcludeCredentials { get; set; } // FIDO2 Keys that are alowed by the user to sign this challenge
        [JsonProperty("authenticatorSelection")]
        public Fido2AuthenticatorSelection AuthenticatorSelection { get; set; } // tell if the FIDO2 CLient should confirm with the user the operation before using FIDO2
        [JsonProperty("attestation", NullValueHandling = NullValueHandling.Ignore)]
        public object attestation { get; set; } // tell if the FIDO2 CLient should confirm with the user the operation before using FIDO2
        [JsonProperty("extensions", NullValueHandling = NullValueHandling.Ignore)]
        public object Extensions { get; set; } // Additional parameters used to ensure better security or other options
    }
}
