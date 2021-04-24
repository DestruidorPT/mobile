using System.Collections.Generic;
using Newtonsoft.Json;

namespace Bit.Core.Models.Data
{
    /// <summary>
    /// Object contains the FIDO2 Key in a simple way
    /// </summary>
    public class Fido2PubKeyCredParam : Data
    {
        [JsonProperty("type")]
        public string Type { get; set; } // type of FIDO2 Key (exemple Public-key)
        [JsonProperty("alg")]
        public int Alg { get; set; } // id of FIDO2 Key
    }
}
