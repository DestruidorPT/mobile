using System.Collections.Generic;
using Newtonsoft.Json;

namespace Bit.Core.Models.Data
{
    /// <summary>
    /// Object contains the FIDO2 Key in a simple way
    /// </summary>
    public class Fido2RP : Data
    {
        [JsonProperty("id")]
        public string Id { get; set; } // id of FIDO2 Key
        [JsonProperty("name")]
        public string Name { get; set; } // id of FIDO2 Key
        [JsonProperty("icon")]
        public string Icon { get; set; } // type of FIDO2 Key (exemple Public-key)
    }
}
