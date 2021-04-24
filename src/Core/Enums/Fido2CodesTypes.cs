using System;
using System.Collections.Generic;
using System.Text;

namespace Bit.Core.Enums
{
    /// <summary>
    /// Enum where contains the code of eash event that fido2 have
    /// </summary>
    public enum Fido2CodesTypes : int
    {
        RequestSignInUser = 994, // for sign in events
        RequestRegisterNewKey = 995, // for regist of new FIDO2 Key events
    }
}
