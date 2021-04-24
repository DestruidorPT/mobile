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

using Bit.Core.Utilities;

namespace Bit.Droid.Fido2System
{
    /// <summary>
    /// Build the requests to the FIDO2 API of Android
    /// Build requests for Sign In or for regist a New Fido 2 Key
    /// </summary>
    class Fido2BuilderDictionary
    {
        private static readonly string _tag_log = "Fido2Builder"; // Tag for the logs in the Fido2Builder

        /// <summary>
        /// Build the request for Sign In using FIDO2
        /// </summary>
        public static PublicKeyCredentialRequestOptions ParsePublicKeyCredentialRequestOptions(Dictionary<string, object> data)
        {
            PublicKeyCredentialRequestOptions.Builder builder = new PublicKeyCredentialRequestOptions.Builder();
            foreach (KeyValuePair<string, object> entry in data)
            {
                switch (entry.Key)
                {
                    case "challenge": // Challenge to be sign
                        builder.SetChallenge(CoreHelpers.Base64UrlDecode((string)entry.Value));
                        break;
                    case "allowCredentials": // List of FIDO2 Keys that already are registered to the user and should only use one of this FIDO2 Keys
                        builder.SetAllowList(ParseCredentialDescriptors((List<Dictionary<string, object>>)entry.Value));
                        break;
                    case "rpId": // Server ID information
                        builder.SetRpId((string)entry.Value);
                        break;
                    case "timeout": // temp limit to sign in
                        builder.SetTimeoutSeconds((Java.Lang.Double)(double) entry.Value);
                        break;
                    case "userVerification": // Require that user has to verify before using FIDO2
                        //Skip
                        break;
                    case "extensions": // Adicional parameter to improve even more the security
                        //Skip
                        break;
                }
            }
            return builder.Build();
        }

        /// <summary>
        /// Build the request for Regist a New FIDO2 Key using FIDO2
        /// </summary>
        public static PublicKeyCredentialCreationOptions ParsePublicKeyCredentialCreationOptions(Dictionary<string, object> data)
        {
            PublicKeyCredentialCreationOptions.Builder builder = new PublicKeyCredentialCreationOptions.Builder();
            foreach (KeyValuePair<string, object> entry in data)
            {
                switch (entry.Key)
                {
                    case "user": // User information
                        builder.SetUser(ParseUser((Dictionary<string, string>) entry.Value));
                        break;
                    case "challenge": // Challenge to be sign
                        builder.SetChallenge(CoreHelpers.Base64UrlDecode((string) entry.Value));
                        break;
                    case "pubKeyCredParams": //Algorithm information
                        builder.SetParameters(ParseParameters((List<Dictionary<string, object>>) entry.Value));
                        break;
                    case "authenticatorSelection": // Options of regist selected
                        builder.SetAuthenticatorSelection(ParseSelection((Dictionary<string, string>)entry.Value));
                        break;
                    case "excludeCredentials": // List of FIDO2 Keys that already are registered to the user and shouldn't be excluded of registering again
                        builder.SetExcludeList(ParseCredentialDescriptors((List<Dictionary<string, object>>) entry.Value));
                        break;
                    case "rpId": // Server ID information
                        builder.SetRp(new PublicKeyCredentialRpEntity((string) entry.Value, null, null));
                        break;
                    case "rp": // Server information
                        builder.SetRp(ParseRp((Dictionary<string, string>) entry.Value));
                        break;
                    case "timeout": // temp limit to regist a new key
                        builder.SetTimeoutSeconds((Java.Lang.Double)(double) entry.Value);
                        break;
                    case "userVerification": // Require that user has to verify before using FIDO2
                        //Skip
                        break;
                    case "attestation": //It is how the signature is given, anonymously or direct.
                        //Skip
                        break;
                }
            }
            return builder.Build();
        }

        /// <summary>
        /// Build the part of request where contains the server information
        /// </summary>
        public static PublicKeyCredentialRpEntity ParseRp(Dictionary<string, string> data)
        {
            string id = null;
            string name = null;
            string icon = null;
            foreach (KeyValuePair<string, string> entry in data)
            {
                switch (entry.Key)
                {
                    case "id": // ID of the server
                        id = entry.Value;
                        break;
                    case "name": // Name of the server, exemple Bitwarden
                        name = entry.Value;
                        break;
                    case "icon": // Icon of the server
                        icon = entry.Value;
                        break;
                }
            }
            return new PublicKeyCredentialRpEntity(id, name, icon);
        }

        /// <summary>
        /// Build the part of request where contains the option to requere the FIDO2 to ask for confirmation
        /// Or for to select the type of key, Platform (Figerprint, PIN) or Cross-platform (NFC, USB, Yubikey) 
        /// </summary>
        public static AuthenticatorSelectionCriteria ParseSelection(Dictionary<string, string> data)
        {
            AuthenticatorSelectionCriteria.Builder builder = new AuthenticatorSelectionCriteria.Builder();
            foreach (KeyValuePair<string, string> entry in data)
            {
                switch (entry.Key)
                {
                    case "authenticatorAttachment": // Selected option, Platform (Figerprint, PIN) or Cross-platform (NFC, USB, Yubikey) 
                        builder.SetAttachment(Attachment.FromString(entry.Value));
                        break;
                    case "userVerification": // Require that user has to verify before using FIDO2
                        //skip
                        break; 
                    case "requireResidentKey": // Require the private key to be saved in exemple in the yubikey internal memory
                        //skip
                        break;
                }
            }
            return builder.Build();
        }

        /// <summary>
        /// Build the part of request where contains the FIDO2 Key information
        /// </summary>
        public static List<PublicKeyCredentialDescriptor> ParseCredentialDescriptors(List<Dictionary<string, object>> listData) 
        {

            List<PublicKeyCredentialDescriptor> credentials = new List<PublicKeyCredentialDescriptor>();
            string id = null;
            string type = null;
            List<Transport> transports = null;
            foreach (Dictionary<string, object> data in listData)
            {
                id = null;
                type = null;
                transports = new List<Transport>();
                foreach (KeyValuePair<string, object> entry in data)
                {
                    switch (entry.Key)
                    {
                        case "id": // id of the FIDO2 key
                            id = (string) entry.Value;
                            break;
                        case "type": // type of the FIDO2 key
                            type = (string) entry.Value;
                            break;
                        case "transports": // list of types of transport accepted (NFC, USB, INTERNAL, BLUETOOTH) of the FIDO2 key
                            foreach (string transport in (List<string>)entry.Value)
                            {
                                 transports.Add(Transport.FromString(transport));
                            }
                            break;
                    }
                }
                credentials.Add(new PublicKeyCredentialDescriptor(type, CoreHelpers.Base64UrlDecode(id), transports));
            }
            return credentials;
        }

        /// <summary>
        /// Build the part of request where contains the user information, exemple name and id
        /// </summary>
        public static PublicKeyCredentialUserEntity ParseUser(Dictionary<string, string> data)
        {
            string id = null;
            string name = null;
            string icon = null;
            string displayName = null;
            foreach (KeyValuePair<string, string> entry in data)
            {
                switch (entry.Key)
                {
                    case "id": // id of user
                        id = entry.Value;
                        break;
                    case "name": // name of user
                        name = entry.Value;
                        break;
                    case "icon": // icon of user
                        icon = entry.Value;
                        break;
                    case "displayName": // name of user to display to the user
                        displayName = entry.Value;
                        break;
                }
            }
            return new PublicKeyCredentialUserEntity(CoreHelpers.Base64UrlDecode(id), name, icon, displayName);
        }

        /// <summary>
        /// Build the part of request where contains the algorithm information
        /// </summary>
        public static List<PublicKeyCredentialParameters> ParseParameters(List<Dictionary<string, object>> listData) 
        {
            List<PublicKeyCredentialParameters> parameters = new List<PublicKeyCredentialParameters>();
            string type = null;
            int alg = 0;
            foreach (Dictionary<string, object> data in listData)
            {
                type = null;
                alg = 0;
                foreach (KeyValuePair<string, object> entry in data)
                {
                    switch (entry.Key)
                    {
                        case "type": // type of algorithm
                            type = (string) entry.Value;
                            break;
                        case "alg": // algorithm selected
                            alg = (int) entry.Value;
                            break;
                    }
                }
                parameters.Add(new PublicKeyCredentialParameters(type, alg));
            }
            return parameters;
        }
    }
}
