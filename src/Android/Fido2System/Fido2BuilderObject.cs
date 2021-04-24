using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Android.App;
using Android.Content;
using Android.Gms.Fido.Common;
using Android.Gms.Fido.Fido2.Api.Common;
using Android.OS;
using Android.Runtime;
using Android.Views;
using Android.Widget;
using Bit.Core.Models.Data;
using Bit.Core.Models.Response;
using Bit.Core.Utilities;

namespace Bit.Droid.Fido2System
{
    /// <summary>
    /// Build the requests to the FIDO2 API of Android
    /// Build requests for Sign In or for regist a New Fido 2 Key
    /// </summary>
    class Fido2BuilderObject
    {
        private static readonly string _tag_log = "Fido2Builder"; // Tag for the logs in the Fido2Builder

        /// <summary>
        /// Build the request for Sign In using FIDO2
        /// </summary>
        public static PublicKeyCredentialRequestOptions ParsePublicKeyCredentialRequestOptions(Fido2AuthenticationChallengeResponse data)
        {
            if(data == null)
            {
                return null;
            }

            PublicKeyCredentialRequestOptions.Builder builder = new PublicKeyCredentialRequestOptions.Builder();

            if(data.Challenge != null && data.Challenge.Length > 0)
            {
                // Challenge to be sign
                builder.SetChallenge(CoreHelpers.Base64UrlDecode(data.Challenge));
            }
            if (data.AllowCredentials != null && data.AllowCredentials.Count > 0)
            {
                // List of FIDO2 Keys that already are registered to the user and should only use one of this FIDO2 Keys
                builder.SetAllowList(ParseCredentialDescriptors(data.AllowCredentials));
            }
            if (data.RpId != null && data.RpId.Length > 0)
            {
                // Server ID information
                builder.SetRpId(data.RpId);
            }
            if (data.Timeout > 0)
            {
                // temp limit to sign in
                builder.SetTimeoutSeconds((Java.Lang.Double)data.Timeout);
            }
            if (data.UserVerification != null)
            {
                // Require that user has to verify before using FIDO2
                //Skip
            }
            if (data.Extensions != null)
            {
                // Adicional parameter to improve even more the security
                //Skip
            }
            return builder.Build();
        }

        /// <summary>
        /// Build the request for Regist a New FIDO2 Key using FIDO2
        /// </summary>
        public static PublicKeyCredentialCreationOptions ParsePublicKeyCredentialCreationOptions(Fido2RegistrationChallengeResponse data)
        {
            if (data == null)
            {
                return null;
            }

            PublicKeyCredentialCreationOptions.Builder builder = new PublicKeyCredentialCreationOptions.Builder();
            if (data.Challenge != null && data.Challenge.Length > 0)
            {
                // Challenge to be sign
                builder.SetChallenge(CoreHelpers.Base64UrlDecode(data.Challenge));
            }
            if (data.ExcludeCredentials != null && data.ExcludeCredentials.Count > 0)
            {
                // List of FIDO2 Keys that already are registered to the user and shouldn't be excluded of registering again
                builder.SetExcludeList(ParseCredentialDescriptors(data.ExcludeCredentials));
            }
            if (data.Timeout > 0)
            {
                // temp limit to regist a new key
                builder.SetTimeoutSeconds((Java.Lang.Double)data.Timeout);
            }
            if (data.User != null)
            {
                // User information
                builder.SetUser(ParseUser(data.User));
            }
            if (data.Rp != null)
            {
                // Server information
                builder.SetRp(ParseRp(data.Rp));
            }
            if (data.PubKeyCredParams != null)
            {
                //Algorithm information
                builder.SetParameters(ParseParameters(data.PubKeyCredParams));
            }
            if (data.AuthenticatorSelection != null)
            {
                // Options of regist selected
                builder.SetAuthenticatorSelection(ParseSelection(data.AuthenticatorSelection));
            }
            if (data.attestation != null)
            {
                // It is how the signature is given, anonymously or direct.
                //Skip
            }
            if (data.Extensions != null)
            {
                // Adicional parameter to improve even more the security
                //Skip
            }
            return builder.Build();
        }

        /// <summary>
        /// Build the part of request where contains the server information
        /// </summary>
        public static PublicKeyCredentialRpEntity ParseRp(Fido2RP data)
        {
            if (data == null)
            {
                return null;
            }

            string id = null;
            string name = null;
            string icon = null;

            if (data.Id != null && data.Id.Length > 0)
            {
                // ID of the server
                id = data.Id;
            }
            if (data.Name != null && data.Name.Length > 0)
            {
                // Name of the server, exemple Bitwarden
                name = data.Name;
            }
            if (data.Icon != null && data.Icon.Length > 0)
            {
                // Icon of the server
                icon = data.Icon;
            }

            return new PublicKeyCredentialRpEntity(id, name, icon);
        }

        /// <summary>
        /// Build the part of request where contains the option to requere the FIDO2 to ask for confirmation
        /// Or for to select the type of key, Platform (Figerprint, PIN) or Cross-platform (NFC, USB, Yubikey) 
        /// </summary>
        public static AuthenticatorSelectionCriteria ParseSelection(Fido2AuthenticatorSelection data)
        {
            if (data == null)
            {
                return null;
            }

            AuthenticatorSelectionCriteria.Builder builder = new AuthenticatorSelectionCriteria.Builder();

            if (data.AuthenticatorAttachment != null && data.AuthenticatorAttachment.Length > 0)
            {
                // Selected option, Platform (Figerprint, PIN) or Cross-platform (NFC, USB, Yubikey) 
                builder.SetAttachment(Attachment.FromString(data.AuthenticatorAttachment));
            }
            if (data.UserVerification != null && data.UserVerification.Length > 0)
            {
                // Require that user has to verify before using FIDO2
                //skip
            }
            if (data.RequireResidentKey != null && data.RequireResidentKey.Length > 0)
            {
                // Require the private key to be saved in exemple in the yubikey internal memory
                //skip
            }

            return builder.Build();
        }

        /// <summary>
        /// Build the part of request where contains the FIDO2 Key information
        /// </summary>
        public static List<PublicKeyCredentialDescriptor> ParseCredentialDescriptors(List<Fido2CredentialDescriptor> listData)
        {
            if (listData == null && listData.Count > 0)
            {
                return new List<PublicKeyCredentialDescriptor>();
            }

            List<PublicKeyCredentialDescriptor> credentials = new List<PublicKeyCredentialDescriptor>();

            string id = null;
            string type = null;
            List<Transport> transports = null;

            foreach (Fido2CredentialDescriptor data in listData)
            {
                id = null;
                type = null;
                transports = new List<Transport>();

                if (data.Id != null && data.Id.Length > 0)
                {
                    // id of the FIDO2 key
                    id = data.Id;
                }
                if (data.Type != null && data.Type.Length > 0)
                {
                    // type of the FIDO2 key
                    type = data.Type;
                }
                if (data.Transports != null && data.Transports.Count > 0)
                {
                    // list of types of transport accepted (NFC, USB, INTERNAL, BLUETOOTH) of the FIDO2 key
                    foreach (string transport in (List<string>)data.Transports)
                    {
                        transports.Add(Transport.FromString(transport));
                    }
                }

                credentials.Add(new PublicKeyCredentialDescriptor(type, CoreHelpers.Base64UrlDecode(id), transports));
            }

            return credentials;
        }

        /// <summary>
        /// Build the part of request where contains the user information, exemple name and id
        /// </summary>
        public static PublicKeyCredentialUserEntity ParseUser(Fido2User data)
        {
            if (data == null)
            {
                return null;
            }

            string id = null;
            string name = null;
            string icon = null;
            string displayName = null;

            if (data.Id != null && data.Id.Length > 0)
            {
                // id of user
                id = data.Id;
            }
            if (data.Name != null && data.Name.Length > 0)
            {
                // name of user
                name = data.Name;
            }
            if (data.Icon != null && data.Icon.Length > 0)
            {
                // icon of user
                icon = data.Icon;
            }
            if (data.DisplayName != null && data.DisplayName.Length > 0)
            {
                // name of user to display to the user
                displayName = data.DisplayName;
            }

            return new PublicKeyCredentialUserEntity(CoreHelpers.Base64UrlDecode(id), name, icon, displayName);
        }

        /// <summary>
        /// Build the part of request where contains the algorithm information
        /// </summary>
        public static List<PublicKeyCredentialParameters> ParseParameters(List<Fido2PubKeyCredParam> listData)
        {
            if (listData == null && listData.Count > 0)
            {
                return new List<PublicKeyCredentialParameters>();
            }

            List<PublicKeyCredentialParameters> parameters = new List<PublicKeyCredentialParameters>();

            string type = null;
            int alg = 0;

            foreach (Fido2PubKeyCredParam data in listData)
            {
                type = null;
                alg = 0;

                if (data.Type != null && data.Type.Length > 0)
                {
                    // type of algorithm
                    type = data.Type;
                }
                if (data.Alg > 0)
                {
                    // algorithm selected
                    alg = data.Alg;
                }

                parameters.Add(new PublicKeyCredentialParameters(type, alg));
            }

            return parameters;
        }
    }
}
