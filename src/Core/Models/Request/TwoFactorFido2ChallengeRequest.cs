namespace Bit.Core.Models.Request
{
    /// <summary>
    /// Request to new FIDO2 data to be sign
    /// </summary>
    public class TwoFactorFido2ChallengeRequest
    {
        public string Email { get; set; } // email of the user
        public string MasterPasswordHash { get; set; } // password hash of the user
    }
}
