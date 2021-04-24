using System.Collections.Generic;
using Newtonsoft.Json;

namespace Bit.Core.Models.Data
{
    /// <summary>
    /// Object contains the FIDO2 Key in a simple way
    /// </summary>
    public class Fido2AuthenticatorSelection : Data
    {
        [JsonProperty("authenticatorAttachment")]
        public string AuthenticatorAttachment { get; set; } // type of FIDO2 Key (exemple Public-key)
        [JsonProperty("userVerification")]
        public string UserVerification { get; set; } // id of FIDO2 Key
        [JsonProperty("requireResidentKey")]
        public string RequireResidentKey { get; set; } // id of FIDO2 Key

        
    }
}
