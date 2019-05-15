using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using AADB2C.PolicyAndKeys.Lib;
using System.Configuration;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AADB2C.PolicyAndKeys.Lib
{
    public class TestRequests
    {
        public const string TESTPARAMETER = "TEST";
        CommandType cmdType = CommandType.EXIT;
        ResourceType resType = ResourceType.POLICIES;
        
        public string TestKeysetID = null;
        private UserMode usrMode;

        public TestRequests(UserMode userMode, ResourceType resourceType,CommandType commandType)
        {
            usrMode = userMode;
            resType = resourceType;
            cmdType = commandType;

        }

        public bool CheckAndGenerateTest(ref string id, ref string content)
        {
            if (resType == ResourceType.POLICIES)

            {
                Console.WriteLine("Test doesnt work with policies");
                cmdType = CommandType.EXIT;
                return false;
            }

            if (id.ToUpper() == TESTPARAMETER)
            {

                switch (cmdType)
                {
                    case CommandType.CREATE:
                    case CommandType.DELETE:
                        content = string.Empty;
                        break;
                    case CommandType.GENERATEKEY:

                        content = Constants.GenerateKey;
                        break;
                    case CommandType.UPDATE:
                        content = Constants.UpdateOctKeyset;


                        break;
                    case CommandType.UPLOADCERTIFICATE:

                        content = Constants.UploadCertificate;
                        break;

                    case CommandType.UPLOADPKCS:
                        content = Constants.UploadPkcs;
                        break;

                    case CommandType.UPLOADSECRET:

                        content = Constants.UploadSecret;

                        break;
                }
                CheckBeforeCreateTestKeyset();
                //id is used in the post/get commands.
                id = TestKeysetID;
                ReplaceTokens(ref content);
                return true;
            }
            return false;
        }

        private void CheckBeforeCreateTestKeyset()
        {
            if (TestKeysetID == null)
            {
                var json = Constants.CreateKeyset;
                var guid = Guid.NewGuid().ToString();

                json = json.Replace(Constants.KEYSETID_TOKEN, guid);
                var req = usrMode.HttpPost(json);
                var content = ExecuteResponse(req);

                TestKeysetID = (string)JToken.Parse(content).SelectToken("id");
            }
        }

        private static string ExecuteResponse(HttpRequestMessage request)
        {
            
            string content = request.Content.ReadAsStringAsync().Result ?? string.Empty;
            HttpClient httpClient = new HttpClient();
            Task<HttpResponseMessage> responseTask = httpClient.SendAsync(request, HttpCompletionOption.ResponseContentRead);

            HttpResponseMessage response = responseTask.Result;

            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine("Error Calling the Graph API HTTP Status={0}", response.StatusCode);
            }

            Console.WriteLine(response.Headers);
            string taskContentString = response.Content.ReadAsStringAsync().Result;
            Console.WriteLine(taskContentString);
            return taskContentString;
        }

        private void ReplaceTokens(ref string s)
        {
            var reg = new Regex(@"#\w+#");
            var mc = reg.Matches(s);

            foreach (Match match in mc)
            {
                foreach (Capture capture in match.Captures)
                {
                    var matched = capture.Value;

                    if (matched == Constants.SECRET_TOKEN)
                    {

                        s = reg.Replace(s, Guid.NewGuid().ToString(), 1);
                    }
                    if (matched == Constants.KEYSETID_TOKEN)
                    {
                        s = reg.Replace(s, TestKeysetID, 1);
                    }
                    if (matched == Constants.NBF_TOKEN)
                    {
                        var nbf = ((DateTimeOffset)DateTime.Now).ToUnixTimeSeconds();
                        s = reg.Replace(s, $"{nbf}", 1);
                    }
                    if (matched == Constants.EXP_TOKEN)
                    {
                        var exp = ((DateTimeOffset)new DateTime(2035, 1, 1)).ToUnixTimeSeconds();
                        s = reg.Replace(s, $"{exp}", 1);
                    }
                }
            }

        }

    }
}
