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

        static CommandType cmdType;
        static ResourceType resType = ResourceType.policies;
        static UserMode userMode;

        public static bool LastCommand { get; private set; }

        private static TestRequests testRequests;

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
                    Console.WriteLine("=========== Custom policy and keyset management demo client. (ctrl+c to exit at any time) ==========");

                    //content is the the request body
                    string cont = string.Empty;
                    //last command is only meant to ensure that this is not the first time.
                    LastCommand = false;
                    //Get resource from console
                    resType = ProcessResourceInput();

                    //Get Command from console
                    cmdType = ProcessCommandInput();

                    //set resource for request to be constructed.
                    userMode.SetResouce(resType, cmdType);

                    //initialize test request
                    testRequests = new TestRequests(userMode, resType, cmdType);
                    switch (cmdType)
                    {
                        case CommandType.LIST:

                            // List all polcies using "GET /trustFrameworkPolicies"
                            request = userMode.HttpGet();
                            ExecuteResponse(request);
                            break;
                        case CommandType.GET:
                            // Get a specific policy using "GET /trustFrameworkPolicies/{id}"
                            args = ProcessParametersInput();
                            testRequests.CheckAndGenerateTest(ref args[0], ref cont);

                            request = userMode.HttpGetID(args[0]);
                            ExecuteResponse(request);

                            break;
                        case CommandType.CREATE:
                            // Create a policy using "POST /trustFrameworkPolicies" with XML in the body
                            args = ProcessParametersInput();

                            if (!testRequests.CheckAndGenerateTest(ref args[0], ref cont))
                            {
                                cont = System.IO.File.ReadAllText(args[0].Replace("\"", ""));
                                request = userMode.HttpPost(cont);
                                ExecuteResponse(request);
                            }


                            break;
                        case CommandType.UPDATE:
                            // Update using "PUT /trustFrameworkPolicies/{id}" with XML in the body
                            args = ProcessParametersInput();

                            if (!testRequests.CheckAndGenerateTest(ref args[0], ref cont))
                            {
                                cont = System.IO.File.ReadAllText(args[1].Replace("\"", ""));
                            }
                            request = userMode.HttpPutID(args[0], cont);
                            ExecuteResponse(request);
                            break;
                        case CommandType.DELETE:
                            // Delete using "DELETE /trustFrameworkPolicies/{id}"
                            args = ProcessParametersInput();

                            testRequests.CheckAndGenerateTest(ref args[0], ref cont);

                            request = userMode.HttpDeleteID(args[0]);
                            ExecuteResponse(request);
                            break;

                        case CommandType.GETACTIVEKEY:
                            args = ProcessParametersInput();

                            request = userMode.HttpGetByCommandType(cmdType, args[0]);
                            ExecuteResponse(request);
                            break;

                        case CommandType.GENERATEKEY:
                        case CommandType.UPLOADSECRET:
                            args = ProcessParametersInput();
                            cont = args.Length == 1 ? string.Empty : args[1];
                            if (!testRequests.CheckAndGenerateTest(ref args[0], ref cont))
                            {
                                testRequests.GenerateKeySetID(ref args[0]);

                            }
                            request = userMode.HttpPostByCommandType(cmdType, args[0], cont);
                            ExecuteResponse(request);
                            break;
                        case CommandType.UPLOADCERTIFICATE:
                        case CommandType.UPLOADPKCS:

                            args = ProcessParametersInput();
                            

                            var bytes = File.ReadAllBytes(args[1].Replace("\"", ""));
                            var base64EncodedString = Convert.ToBase64String(bytes);
                            string UploadCertificate = @"{{  'key': '{0}' }} ";

                            string UploadPkcs = @"{{  'key': '{0}',   'password': '{1}' }}";
                            if (cmdType == CommandType.UPLOADPKCS)
                            {
                                cont = string.Format(UploadPkcs, base64EncodedString, args[2]);
                            }
                            else if (cmdType == CommandType.UPLOADCERTIFICATE)
                            {
                                
                                cont = string.Format(UploadCertificate, base64EncodedString);
                            }


                            if (!testRequests.CheckAndGenerateTest(ref args[0], ref cont))
                            {
                                testRequests.GenerateKeySetID(ref args[0]);

                            }


                            request = userMode.HttpPostByCommandType(cmdType, args[0], cont);
                            ExecuteResponse(request);
                            break;
                        case CommandType.EXIT:
                            //setting lastCommand = true, because we have recieved command
                            LastCommand = true;
                            CheckLastCommandAndExitApp();
                            break;
                    }



                } while (cmdType != CommandType.EXIT);

            }
            catch (Exception e)
            {
                Print(request);
                Console.WriteLine("\nError {0} {1}", e.Message, e.InnerException != null ? e.InnerException.Message : "");
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
                case CommandType.UPLOADSECRET:

                    Console.WriteLine($"For Command: {cmdType.ToString()} (space separated) specify Id and path of {resType.ToString()} ");
                    if (resType != ResourceType.policies) Console.WriteLine("optionally, type test for both, if you want to simply try this out");
                    break;

                case CommandType.UPLOADCERTIFICATE:
                    Console.WriteLine($"For Command: {cmdType.ToString()} (space separated) specify Id of container and path to cer file");
                    break;
                case CommandType.UPLOADPKCS:
                    Console.WriteLine($"For Command: {cmdType.ToString()} (space separated) specify Id of container and path to pfx file and password ");
                    break;

            }
            Console.Write(":> ");
            var pars = Console.ReadLine();

            if (string.IsNullOrWhiteSpace(pars))
            {
                ProcessParametersInput();

            }


            var parsArray = Regex.Split(pars, "\\s(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
            parameters = new List<string>(parsArray);
            if ((cmdType == CommandType.UPDATE && parameters.Count != 2) ||
                (cmdType == CommandType.UPLOADCERTIFICATE && parameters.Count != 2) ||
                (cmdType == CommandType.UPLOADPKCS && parameters.Count != 3) || 
                parameters.Any(string.Empty.Contains))
            {
                ProcessParametersInput();
            }

            return parameters.ToArray();
        }

        private static CommandType ProcessCommandInput()
        {
            CheckLastCommandAndExitApp();
            var commands = Enum.GetNames(typeof(CommandType));
            Console.WriteLine("Which command do you want to execute on - {0}. ", string.Join(", ", commands));
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
            Console.WriteLine("Which resource do you want to execute on (enter name below) - {0} or {1}.", resources[0], resources[1]);
            Console.Write(":> ");
            var resource = Console.ReadLine().ToUpper();
            if (!resources.Any(r => r.Equals(resource, StringComparison.OrdinalIgnoreCase)))
            {
                Console.WriteLine("Please enter a valid choice.");
                ProcessResourceInput();
            }
            else
            {
                resType = (ResourceType)Enum.Parse(typeof(ResourceType), resource, true);
            }

            return resType;
        }

        private static string ExecuteResponse(HttpRequestMessage request)
        {
            Print(request);
            if (request.Content != null)
            {
                string content = request.Content.ReadAsStringAsync().Result ?? string.Empty;
                PrintInfo(content);
            }

            HttpClient httpClient = new HttpClient();
            Task<HttpResponseMessage> response = httpClient.SendAsync(request, HttpCompletionOption.ResponseContentRead);

            return Print(response);
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
            try
            {
                Console.WriteLine(JValue.Parse(taskContentString).ToString(Formatting.Indented));
            }
            catch
            {
                Console.WriteLine(taskContentString);
            }

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
                Console.WriteLine("Enter any character or simply enter to exit");
                Console.ReadKey();
                Console.WriteLine("bye bye...");
                Environment.Exit(0);

            }

        }


    }
}
