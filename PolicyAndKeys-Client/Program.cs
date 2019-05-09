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

namespace AADB2C.PolicyAndKeys.Client
{
    public class Program
    {
        private const string TESTPARAMETER = "TEST";

        // Client ID is the application guid used uniquely identify itself to the v2.0 authentication endpoint
        public static string ClientIdForUserAuthn = "ENTER_YOUR_CLIENT_ID";

        // Your tenant Name, for example "myb2ctenant.onmicrosoft.com"
        public static string Tenant = "ENTER_YOUR_TENANT_NAME";


        static CommandType cmdType = CommandType.EXIT;
        static ResourceType resType = ResourceType.POLICIES;
        static UserMode userMode;

        static string TestKeysetID = null;

        public static bool LastCommand { get; private set; }

        static void Main(string[] args)
        {
            // validate parameters
            
            var appSettings = ConfigurationManager.AppSettings;
            ClientIdForUserAuthn = appSettings["ida:ClientId"];
            Tenant = appSettings["ida:Tenant"];

            if (!CheckConfiguration(args))
                return;

            HttpRequestMessage request = null;
            var authHelper = new AuthenticationHelper(ClientIdForUserAuthn, Tenant);
            ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;

            try
            {
                // Login as global admin of the Azure AD B2C tenant
                authHelper.LoginAsAdmin();
                // Graph client does not yet support trustFrameworkPolicy, so using HttpClient to make rest calls
                userMode = new UserMode(authHelper.TokenForUser);

                do
                {
                    LastCommand = false;   
                    resType = ProcessResourceInput();
                    userMode.SetResouce(resType);

                    cmdType = ProcessCommandInput();
                    switch (cmdType)
                    {
                        case CommandType.LIST:

                            // List all polcies using "GET /trustFrameworkPolicies"
                            PrintInfo("");
                            request = userMode.HttpGet();
                            break;
                        case CommandType.GET:
                            // Get a specific policy using "GET /trustFrameworkPolicies/{id}"
                            args = ProcessParametersInput();
                            PrintInfo("", args[0]);
                            request = userMode.HttpGetID(args[1]);
                            break;
                        case CommandType.CREATE:
                            // Create a policy using "POST /trustFrameworkPolicies" with XML in the body
                            args = ProcessParametersInput();

                            string cont = System.IO.File.ReadAllText(args[0]);
                            PrintInfo("", args[0]);
                            request = userMode.HttpPost(cont);
                            break;
                        case CommandType.UPDATE:
                            // Update using "PUT /trustFrameworkPolicies/{id}" with XML in the body
                            args = ProcessParametersInput();
                            cont = System.IO.File.ReadAllText(args[1]);
                            PrintInfo("", args[0], args[1]);
                            request = userMode.HttpPutID(args[0], cont);
                            break;
                        case CommandType.DELETE:
                            // Delete using "DELETE /trustFrameworkPolicies/{id}"
                            args = ProcessParametersInput();

                            PrintInfo("", args[0]);
                            request = userMode.HttpDeleteID(args[0]);
                            break;

                        case CommandType.BACKUPKEYSETS:
                        case CommandType.GETACTIVEKEY:
                            args = ProcessParametersInput();

                            PrintInfo("", args[0]);
                            request = userMode.HttpGetByCommandType(cmdType, args[0]);
                            break;

                        case CommandType.GENERATEKEY:
                        case CommandType.UPLOADCERTIFICATE:
                        case CommandType.UPLOADPKCS:
                        case CommandType.UPLOADSECRET:
                            args = ProcessParametersInput();
                            var id = args[0];
                            PrintInfo("", id);

                            cont = args.Length == 1 ? string.Empty : args[1];
                            if (!CheckAndGenerateTest(ref id, ref cont))
                            {
                                if (cont.Contains(Path.DirectorySeparatorChar))
                                    cont = File.ReadAllText(args[1]);
                            }
                            request = userMode.HttpPostByCommandType(cmdType, id, cont);
                            break;
                        case CommandType.EXIT:
                            CheckLastCommandAndExitApp();
                            break;
                    }

                    ExecuteResponse(request);

                } while (cmdType != CommandType.EXIT);

            }
            catch (Exception e)
            {
                Print(request);
                Console.WriteLine("\nError {0} {1}", e.Message, e.InnerException != null ? e.InnerException.Message : "");
            }
        }

        private static string ExecuteResponse(HttpRequestMessage request)
        {
            Print(request);

            HttpClient httpClient = new HttpClient();
            Task<HttpResponseMessage> response = httpClient.SendAsync(request, HttpCompletionOption.ResponseContentRead);
            
            return Print(response);
        }

        private static bool CheckAndGenerateTest(ref string id, ref string content)
        {
            if (id.ToUpper() == TESTPARAMETER)
            {
                switch (cmdType)
                {
                    case CommandType.GENERATEKEY:
                        
                        content = Constants.GenerateKey;
                        break;
                    case CommandType.UPDATE:
                        content= Constants.UpdateOctKeyset;

                        
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

        private static void ReplaceTokens(ref string s)
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
        
        private static void CheckBeforeCreateTestKeyset()
        {
            if (TestKeysetID == null)
            {
                var json = Constants.CreateKeyset;
                var guid = Guid.NewGuid().ToString();
                
                ReplaceTokens(ref json);
                var req = userMode.HttpPost(json);
                var content = ExecuteResponse(req);
                TestKeysetID = (string) JToken.Parse(content).SelectToken("id");
            }
        }

        private static string[] ProcessParametersInput()
        {
            CheckLastCommandAndExitApp();
            List<string> parameters = new List<string>();
            Console.WriteLine($"For Resource {resType.ToString()} and Command {cmdType.ToString()} ");

            switch (cmdType)
            {
                case CommandType.DELETE:
                // Delete using "DELETE /trustFrameworkPolicies/{id}"
                case CommandType.GET:
                case CommandType.BACKUPKEYSETS:
                case CommandType.GETACTIVEKEY:
                case CommandType.GENERATEKEY:
                    // Get a specific policy using "GET /trustFrameworkPolicies/{id}"
                    Console.WriteLine($"For Command: {cmdType.ToString()} Enter Id of {resType.ToString()} ");
                    if (cmdType == CommandType.GENERATEKEY) Console.WriteLine("optionally, type test, if you want to simply try this out");
                    break;
                case CommandType.CREATE:
                    // Create a policy using "POST /trustFrameworkPolicies" with XML in the body
                    Console.WriteLine($"For Command: {cmdType.ToString()} specify path of {resType.ToString()} ");
                    break;
                case CommandType.UPDATE:
                case CommandType.UPLOADCERTIFICATE:
                case CommandType.UPLOADPKCS:
                case CommandType.UPLOADSECRET:
                    // Update using "PUT /trustFrameworkPolicies/{id}" with XML in the body
                    Console.WriteLine($"For Command: {cmdType.ToString()} (space separated) specify Id and path of {resType.ToString()} ");
                    if (resType != ResourceType.POLICIES) Console.WriteLine("optionally, type test for both, if you want to simply try this out");
                    break;

            }
            Console.Write(":> ");
            var pars = Console.ReadLine();

            if (string.IsNullOrWhiteSpace(pars))
            {
                ProcessParametersInput();

            }


            var parsArray = pars.Split(' ');
            parameters = new List<string>(parsArray);
            if ((cmdType == CommandType.UPDATE && parameters.Count != 2) || parameters.Any(string.Empty.Contains))
            {
                ProcessParametersInput();
            }

            return parameters.ToArray();
        }

        private static CommandType ProcessCommandInput()
        {
            CheckLastCommandAndExitApp();
            var commands = Enum.GetNames(typeof(CommandType));
            Console.WriteLine("Which command do you want to execute on {0} ", string.Join(",", commands));
            Console.Write(":> ");
            var command = Console.ReadLine().ToUpper();
            if (!commands.Any(command.Contains))
            {

                cmdType = ProcessCommandInput();
            }
            else
            {
                cmdType = (CommandType)Enum.Parse(typeof(CommandType), command);
            }

            return cmdType;
        }

        private static ResourceType ProcessResourceInput()
        {
            CheckLastCommandAndExitApp();
            var resources = Enum.GetNames(typeof(ResourceType));
            Console.WriteLine("Policy and Keyset Client (type exit at any time)");
            Console.WriteLine("Which resource do you want to execute on {0} or {1}", resources[0], resources[1]);
            Console.Write(":> ");
            var resource = Console.ReadLine().ToUpper();
            if (!resources.Any(resource.Contains))
            {
                ProcessResourceInput();
            }
            else
            {
                resType = (ResourceType)Enum.Parse(typeof(ResourceType), resource);
            }

            return resType;
        }

        public static bool CheckConfiguration(string[] args)
        {
            if (ClientIdForUserAuthn.Equals("ENTER_YOUR_CLIENT_ID") ||
                Tenant.Equals("ENTER_YOUR_TENANT_NAME"))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("1. Open 'app.config'");
                Console.WriteLine("2. Update 'ida:ClientId'");
                Console.WriteLine("3. Update 'ida:Tenant'");
                Console.WriteLine("");
                Console.WriteLine("See README.md for detailed instructions.");
                Console.WriteLine("");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("[press any key to exit]");
                Console.ReadKey();
                return false;
            }

            return true;
        }

        public static void PrintInfo(string print, params string[] args)
        {
            args = args ?? (new List<string>()).ToArray<string>();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(print + $" {resType.ToString()}  {cmdType.ToString()}");
            Console.WriteLine("{0}", string.Join(" ", args));
            Console.ForegroundColor = ConsoleColor.White;
        }

        public static string Print(Task<HttpResponseMessage> responseTask)
        {
            responseTask.Wait();
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

        public static void Print(HttpRequestMessage request)
        {
            if (request != null)
            {
                Console.Write(request.Method + " ");
                Console.WriteLine(request.RequestUri);
                Console.WriteLine("");
            }
        }

        private static void CheckLastCommandAndExitApp()
        {
            if (LastCommand && cmdType == CommandType.EXIT)
            {
                LastCommand = true;
                Console.WriteLine("bye bye...");
                Environment.Exit(0);

            }
        }

        
    }
}
