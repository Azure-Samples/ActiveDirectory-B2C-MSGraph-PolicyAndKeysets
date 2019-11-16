using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

namespace AADB2C.PolicyAndKeys.Lib
{
    public enum ResourceType
    {
        policies = 1,
        keySets = 2
    }

    public enum CommandType
    {
        EXIT = 0, 
        LIST = 1 , 
        GET = 2, 
        CREATE = 3, 
        UPDATE = 4, 
        DELETE = 5, 
        GENERATEKEY = 6, 
        UPLOADSECRET = 7, 
        UPLOADCERTIFICATE = 8, 
        UPLOADPKCS = 9, 
        GETACTIVEKEY = 10,         
    }

    public class UserMode
    {
        static string ContentType = "application/xml";
        static string resourceType = "policies";
        static string TFUri = $"https://graph.microsoft.com/beta/trustFramework/{resourceType}";
        static string TFByIDUri = $"https://graph.microsoft.com/beta/trustFramework/{resourceType}/{0}";

        //specific key related APIS
        //POST https://graph.microsoft.com/beta/trustFramework/keySets/{id}/uploadSecret {  "use": "sig",  "k": "sdkalsdasdlasdlvasdasdbvlabdlv",  "nbf": "1508969811",  "exp": "1508973711", } 
        public static string TFKeysetsUploadSecret = "https://graph.microsoft.com/beta/trustFramework/keySets/{0}/uploadSecret";

        //POST https://graph.microsoft.com/beta/trustFramework/keySets/{id}/uploadCertificate {  "key": "sdkalsdasdlasdlvasdasdbvlabdlv" }
        public static string TFKeysetsUploadCertificate = "https://graph.microsoft.com/beta/trustFramework/keySets/{0}/uploadCertificate";

        //POST https://graph.microsoft.com/beta/trustFramework/keySets/{id}/uploadPkcs12 {  "key": "sdkalsdasdlasdlvasdasdbvlabdlv",   "password": "skdjskdj" } 
        public static string TFKeysetsUploadPkcs12 = "https://graph.microsoft.com/beta/trustFramework/keySets/{0}/uploadPkcs12";

        //POST https://graph.microsoft.com/beta/trustFramework/keySets/{id}/generateKey {  "use": "sig",  "kty": "RSA",  "nbf": "1508969811",  "exp": "1508973711", } 
        public static string TFKeysetGenerateKey = "https://graph.microsoft.com/beta/trustFramework/keySets/{0}/generateKey";

        //GET https://graph.microsoft.com/beta/trustFramework/keySets/{id}/getActiveKey 
        public static string TFKeysetActiveKey = "https://graph.microsoft.com/beta/trustFramework/keySets/{0}/getActiveKey";


        public string TokenForUser { get; private set; }

        public UserMode(string token)
        {
            TokenForUser = token;
        }

        public void SetResouce(ResourceType resource, CommandType cmdType)
        {
            resourceType = resource.ToString();
            TFUri = $"https://graph.microsoft.com/beta/trustFramework/{resourceType}";
            TFByIDUri = $"https://graph.microsoft.com/beta/trustFramework/{resourceType}/" + "{0}";
            if (resource == ResourceType.policies && cmdType != CommandType.DELETE)
                TFByIDUri = TFByIDUri + "/$value";

            if (resource == ResourceType.keySets)
                ContentType = "application/json";
        }
        public HttpRequestMessage HttpGet()
        {
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, TFUri);
            AddHeaders(request);
            return request;
        }

        public HttpRequestMessage HttpGetByCommandType(CommandType cmdType, string id)
        {
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, TFUri);

            switch (cmdType)
            {
                case CommandType.GETACTIVEKEY:
                    request =  new HttpRequestMessage(HttpMethod.Get, string.Format(TFKeysetActiveKey, id));
                    break;                
            }

            AddHeaders(request);
            return request;
        }
        public HttpRequestMessage HttpGetID(string id)
        {
            string uriWithID = String.Format(TFByIDUri, id);
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, uriWithID);
            AddHeaders(request);
            return request;
        }

        public HttpRequestMessage HttpPutID(string id, string content)
        {
            string uriWithID = String.Format(TFByIDUri, id);
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Put, uriWithID);
            AddHeaders(request);
            request.Content = new StringContent(content, Encoding.UTF8, ContentType);
            return request;
        }

        public HttpRequestMessage HttpPost(string content)
        {
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, TFUri);
            AddHeaders(request);
            request.Content = new StringContent(content, Encoding.UTF8, ContentType);
            return request;
        }

        public HttpRequestMessage HttpPostByCommandType(CommandType cmdType, string id, string content)
        {
            string uri = TFUri;
            
            switch (cmdType)
            {
                case CommandType.GENERATEKEY:
                    uri = string.Format(TFKeysetGenerateKey, id);
                    break;
                case CommandType.UPLOADSECRET:
                    uri = string.Format(TFKeysetsUploadSecret, id);
                    
                    break;
                case CommandType.UPLOADPKCS:
                    uri = string.Format(TFKeysetsUploadPkcs12, id);
                    
                    break;
                case CommandType.UPLOADCERTIFICATE:
                    uri = string.Format(TFKeysetsUploadCertificate, id);
                    
                    break;
            }


            return HttpPost(uri, content);
        }
        public HttpRequestMessage HttpPost(string uri, string content)
        {
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, uri);
            AddHeaders(request);
            request.Content = new StringContent(content, Encoding.UTF8, ContentType);
            return request;
        }

        //Delete https://graph.microsoft.com/beta/trustFramework/keySets/{id} 
        public HttpRequestMessage HttpDeleteID(string id)
        {
            string uriWithID = String.Format(TFByIDUri, id);
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Delete, uriWithID);
            AddHeaders(request);
            return request;
        }

        void AddHeaders(HttpRequestMessage requestMessage)
        {
            if (TokenForUser == null)
            {
                Debug.WriteLine("Call GetAuthenticatedClientForUser first");
            }

            try
            {
                requestMessage.Headers.Authorization = new AuthenticationHeaderValue("bearer", TokenForUser);
                //requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(ContentType));

                requestMessage.Headers.Add("SampleID", "console-csharp-trustframeworkpolicy");
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Could not add headers to HttpRequestMessage: " + ex.Message);
            }
        }

        public static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }

    }

}
