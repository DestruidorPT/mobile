using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Android.App;
using Android.Content;
using Android.OS;
using Android.Runtime;
using Android.Views;
using Android.Widget;
using Java.Util.Concurrent;
using Android.Gms.Fido;
using Android.Gms.Fido.Fido2;
using Android.Gms.Fido.Fido2.Api.Common;
using Bit.Core.Enums;
using Android.Util;
using AndroidX.AppCompat.App;
using Android.Gms.Tasks;
using Newtonsoft.Json;
using System.IO;
using Bit.Core.Utilities;
using Bit.Core.Abstractions;
using Bit.Core.Models.Request;
using Bit.Core.Models.Response;
using Bit.Core.Models.Data;
using Bit.App.Resources;

namespace Bit.Droid.Fido2System
{
    /// <summary>
    /// Service to treat the FIDO2 information and errors, and to inicialize the FIDO2 on Android
    /// </summary>
    public class Fido2Service
    {
        public static readonly string _tag_log = "Fido2Service"; // Tag for the logs in the FIDO2 Service
        public static readonly string _tag_for_user = "Fido2"; // Tag for erros to show to the user
        private Fido2ApiClient fido2ApiClient;
        private Fido2CodesTypes fido2CodesType;
        private readonly IApiService _apiService;
        private readonly IAuthService _authService;
        private readonly II18nService _i18nService;
        private readonly IPlatformUtilsService _platformUtilsService;
        private AppCompatActivity application;
        public static Fido2Service INSTANCE = new Fido2Service();

        public Fido2Service() {
            this._apiService = ServiceContainer.Resolve<IApiService>("apiService");
            this._authService = ServiceContainer.Resolve<IAuthService>("authService");
            this._i18nService = ServiceContainer.Resolve<II18nService>("i18nService");
            this._platformUtilsService = ServiceContainer.Resolve<IPlatformUtilsService>("platformUtilsService");
        }

        /// <summary>
        /// To iniciate the FIDO2 Service with the activity given
        /// </summary>
        public void start(AppCompatActivity application)
        {
            this.application = application;
            this.fido2ApiClient = Fido.GetFido2ApiClient(this.application); // Start FIDO2 Client from the Android 
        }

        /// <summary>
        /// To iniciate the FIDO2 Service with the activity given
        /// </summary>
        public void OnActivityResult(int requestCode, Result resultCode, Intent data)
        {
            // Check if the event code is a match to any event code of FIDO2
            if (resultCode == Result.Ok && Enum.IsDefined(typeof(Fido2CodesTypes), requestCode))
            {
                byte[] errorExtra = null;
                switch ((Fido2CodesTypes)requestCode)
                {
                    case Fido2CodesTypes.RequestSignInUser: // Check if the event is to sign in a user using FIDO2
                        errorExtra = data.GetByteArrayExtra(Fido.Fido2KeyErrorExtra); // Get errors if exist
                        if (errorExtra != null) // Check if exist erros
                        {
                            //Show a message of erro to the user
                            this.HandleErroCode(errorExtra);
                        }
                        else
                        {
                            if (data != null)
                            {
                                // Send the response to the server, where the data is signed to authenticate using FIDO2 two-factor
                                this.SignInUserResponse(data);
                            }
                        }
                        break;
                    // If in the future the bitwarden wants to add the regist of keys in the android 
                    /*case Fido2CodesTypes.RequestRegisterNewKey:
                        errorExtra = data.GetByteArrayExtra(Fido.Fido2KeyErrorExtra);
                        if (errorExtra != null)
                        {
                            this.HandleErroCode(errorExtra);
                        }
                        else
                        {
                            if (data != null)
                            {
                                
                            }
                        }
                        break;*/
                }
            }
            else if (resultCode == Result.Canceled && Enum.IsDefined(typeof(Fido2CodesTypes), requestCode))
            {
                // FIDO2 from what was tested, the FIDO2 Android send a "Fido2KeyErrorExtra" even when canceled
                // this is just in case in the future that change
                Log.Info(_tag_log, "cancelled");
                this._platformUtilsService.ShowDialogAsync(this._i18nService.T("Fido2AbortErro"), _tag_for_user);
            }
        }

        /// <summary>
        /// To treat any success events for the FIDO2
        /// </summary>
        public void OnSuccess(Java.Lang.Object result)
        {
            // Check if the success event is for FIDO2 Service
            if (result != null && Enum.IsDefined(typeof(Fido2CodesTypes), this.fido2CodesType))
            {
                try
                {
                    // Start the FIDO2 from the Android on this activity
                    this.application.StartIntentSenderForResult(((PendingIntent)result).IntentSender, (int)this.fido2CodesType, null, 0, 0, 0);
                }
                catch (Exception e)
                {
                    Log.Error(_tag_log, e.Message);
                    // To show to the user, that something went wrong
                    this._platformUtilsService.ShowDialogAsync(this._i18nService.T("Fido2SomethingWentWrong"), _tag_for_user);
                }
            }
        }

        /// <summary>
        /// To treat any failure events for the FIDO2
        /// </summary>
        public void OnFailure(Java.Lang.Exception e)
        {
            Log.Error(_tag_log, e.Message);
            // To show to the user, that something went wrong
            this._platformUtilsService.ShowDialogAsync(this._i18nService.T("Fido2SomethingWentWrong"), _tag_for_user);
        }

        /// <summary>
        /// To treat any complete events for the FIDO2
        /// </summary>
        public void OnComplete(Task task)
        {

        }

        /// <summary>
        /// Start the FIDO2 Sign in type on Android.
        /// </summary>
        public async System.Threading.Tasks.Task SignInUserRequestAsync(string dataJson = "")
        {
            try
            {
                Fido2AuthenticationChallengeResponse dataObject = null; // Data to sign, given from the server
                if (dataJson != null && dataJson.Length > 0) // Authenticate using the token, but because the token don t received the origin of this aplication this cannot be used for now.
                {
                    // transform the token JSON to a object
                    // The reason to use class for de deserializa is because of bugs that appears when using Dictionary<string, object> in the number section
                    dataObject = Newtonsoft.Json.JsonConvert.DeserializeObject<Fido2AuthenticationChallengeResponse>(dataJson);
                } else
                {
                    // Preparing to request to the server the information about FIDO2
                    var request = new TwoFactorFido2ChallengeRequest
                    {
                        Email = this._authService.Email,
                        MasterPasswordHash = this._authService.MasterPasswordHash
                    };
                    // Send the request to the API Service
                    dataObject = await this._apiService.GetTwoFactorFido2AuthenticationChallengeAsync(request);
                }
                // Save the event code that will be started
                this.fido2CodesType = Fido2CodesTypes.RequestSignInUser;
                // Start the FIDO2 API from the Android code, using the data build in Fido2 Builder
                var task = this.fido2ApiClient.GetSignPendingIntent(Fido2BuilderObject.ParsePublicKeyCredentialRequestOptions(dataObject));
                task.AddOnSuccessListener((IOnSuccessListener)this.application)
                        .AddOnFailureListener((IOnFailureListener)this.application)
                            .AddOnCompleteListener((IOnCompleteListener)this.application);
            }
            catch (Exception e)
            {
                Log.Error(_tag_log, e.Message);
            }
            finally
            {
                Log.Info(_tag_log, "SignInUserRequest() -> finally()");
            }
        }

        /// <summary>
        /// Create the response to the server, for it to be validate
        /// </summary>
        private void SignInUserResponse(Intent data)
        {
            try
            {
                // Extract the AuthenticatorAssertionResponse.
                AuthenticatorAssertionResponse response = AuthenticatorAssertionResponse.DeserializeFromBytes(data.GetByteArrayExtra(Fido.Fido2KeyResponseExtra));
                // Preparing the response
                var responseJson = Newtonsoft.Json.JsonConvert.SerializeObject(new Fido2AuthenticationChallengeRequest
                {
                        Id = CoreHelpers.Base64UrlEncode(response.GetKeyHandle()),
                        RawId = CoreHelpers.Base64UrlEncode(response.GetKeyHandle()),
                        Type = "public-key",
                        Response = new Fido2AssertionResponse
                        {
                            AuthenticatorData = CoreHelpers.Base64UrlEncode(response.GetAuthenticatorData()),
                            ClientDataJson = CoreHelpers.Base64UrlEncode(response.GetClientDataJSON()),
                            Signature = CoreHelpers.Base64UrlEncode(response.GetSignature()),
                            UserHandle = (response.GetUserHandle()!=null?CoreHelpers.Base64UrlEncode(response.GetUserHandle()):null),
                        },
                        Extensions = null
                }
                );
                // Sending the response
                // Messaging Service doesn't run completed if is on UI Thread, this (Device.BeginInvokeOnMainThread) is just to use message service out of UI Thread
                Xamarin.Forms.Device.BeginInvokeOnMainThread(()=>((MainActivity)this.application).Fido2Submission(responseJson));
            } catch (Exception e) {
                Log.Error(_tag_log, e.Message);
            } finally
            {
                Log.Info(_tag_log, "SignInUserResponse() -> finally()");
            }
        }

        /// <summary>
        /// Handle Android FIDO2 error and display the message associated with the error
        /// </summary>
        public void HandleErroCode(byte[] errorExtra)
        {
            var error = AuthenticatorErrorResponse.DeserializeFromBytes(errorExtra);
            if (error.ErrorMessage.Length > 0)
            {
                Log.Info(_tag_log, error.ErrorMessage);
            }
            string message = "";
            if (error.ErrorCode == ErrorCode.AbortErr) {
                // The operation was aborted.
                message = "Fido2AbortErro";
            }
            else if (error.ErrorCode == ErrorCode.TimeoutErr) {
                // The operation timed out.
                message = "Fido2TimeoutErro";
            }
            else if (error.ErrorCode == ErrorCode.AttestationNotPrivateErr) {
                // The authenticator violates the privacy requirements of the AttestationStatementType it is using.
                message = "Fido2PrivacyErro";
            }
            else if (error.ErrorCode == ErrorCode.ConstraintErr) {
                // A mutation operation in a transaction failed because a constraint was not satisfied.
                message = "Fido2SomethingWentWrong";
            }
            else if (error.ErrorCode == ErrorCode.DataErr) {
                // Provided data is inadequate.
                message = "Fido2ServerDataFail";
            }
            else if (error.ErrorCode == ErrorCode.EncodingErr) {
                // The encoding operation (either encoded or decoding) failed.
                message = "Fido2SomethingWentWrong";
            }
            else if (error.ErrorCode == ErrorCode.InvalidStateErr) {
                // The object is in an invalid state.
                message = "Fido2SomethingWentWrong";
            }
            else if (error.ErrorCode == ErrorCode.NetworkErr) {
                // A network error occurred.
                message = "Fido2NetworkFail";
            }
            else if (error.ErrorCode == ErrorCode.NotAllowedErr) {
                // The request is not allowed by the user agent or the platform in the current context, possibly because the user denied permission.
                message = "Fido2NoPermission";
            }
            else if (error.ErrorCode == ErrorCode.NotSupportedErr) {
                // The operation is not supported.
                message = "Fido2NotSupportedErro";
            }
            else if (error.ErrorCode == ErrorCode.SecurityErr) {
                // The operation is insecure.
                message = "Fido2SecurityErro";
            }
            else if (error.ErrorCode == ErrorCode.UnknownErr) {
                // The operation failed for an unknown transient reason.
                message = "Fido2SomethingWentWrong";
            }
            else {
                // Other future errors
                message = "Fido2SomethingWentWrong";
            }
            // Show the message of error
            this._platformUtilsService.ShowDialogAsync(this._i18nService.T(message), _tag_for_user);
        }
    }
}
