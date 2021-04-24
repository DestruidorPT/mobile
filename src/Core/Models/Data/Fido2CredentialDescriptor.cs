using System.Collections.Generic;
using Newtonsoft.Json;

namespace Bit.Core.Models.Data
{
    /// <summary>
    /// Object contains the FIDO2 Key in a simple way
    /// </summary>
    public class Fido2CredentialDescriptor : Data
    {
        [JsonProperty("type")]
        public string Type { get; set; } // type of FIDO2 Key (exemple Public-key)
        [JsonProperty("id")]
        public string Id { get; set; } // id of FIDO2 Key
        [JsonProperty("transports", NullValueHandling = NullValueHandling.Ignore)]
        public List<string> Transports { get; set; } // list of autenticate types (NFC, USB, INTERNAL, BLUETOOTH) allowed on the FIDO2 Key
    }
}
