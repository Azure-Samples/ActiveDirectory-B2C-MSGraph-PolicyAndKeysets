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
        ResourceType resType = ResourceType.policies;

        public string TestKeysetID = null;
        private UserMode usrMode;

        public TestRequests(UserMode userMode, ResourceType resourceType, CommandType commandType)
        {
            usrMode = userMode;
            resType = resourceType;
            cmdType = commandType;

        }

        public bool CheckAndGenerateTest(ref string id, ref string content)
        {
            if (resType == ResourceType.policies)
            {
                //Console.WriteLine("Test doesnt work with policies");
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

        private static Random random = new Random();
        private static string RandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }
        private void CheckBeforeCreateTestKeyset()
        {
            if (TestKeysetID == null)
            {
                var json = Constants.CreateKeyset;

                json = json.Replace(Constants.KEYSETID_TOKEN, RandomString(8));
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

       

        public void ReplaceTokens(ref string s)
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
                        var guid = Guid.NewGuid().ToString();
                        if (cmdType == CommandType.UPLOADCERTIFICATE || cmdType == CommandType.UPLOADPKCS)
                        {
                            throw new InvalidOperationException("UPLOADCERTIFICATE and UPLOADPKCS is not supported in test mode");
                        }
                        else
                        {

                            s = reg.Replace(s, Guid.NewGuid().ToString(), 1);
                        }
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

        public void GenerateKeySetID(ref string id)
        {
            var json = Constants.CreateKeyset;

            json = json.Replace(Constants.KEYSETID_TOKEN, id);
            var req = usrMode.HttpPost(json);
            var content = ExecuteResponse(req);
            var result = JToken.Parse(content);

            var keySetId = (string)result.SelectToken("id");

            if (keySetId is null)
            {
                var errorCode = (string)result.SelectToken("error.code");
                if (errorCode == "AADB2C95028")
                {
                    // KeySet is already exists. Manually returning key by appending B2C_1A_
                    keySetId = "B2C_1A_" + id;

                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Key Set with KeyID {keySetId} already exists and Graph API use existing key set id to add keys.");
                    Console.ForegroundColor = ConsoleColor.White;
                }
            }

            id = keySetId;
        }

    }
}
