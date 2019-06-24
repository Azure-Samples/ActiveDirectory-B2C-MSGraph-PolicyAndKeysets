using System.Collections.Generic;

namespace AADB2C.PolicyAndKeys.Lib
{
    public class Constants
    {
        public const string SECRET_TOKEN = "#secret#";

        public const string KEYSETID_TOKEN = "#keysetid#";

        public const string NBF_TOKEN = "#nbf#";

        public const string EXP_TOKEN = "#exp#";

        public static string CreateKeyset = @"{{  
                                                 'id': '{0}'
                                                }}";

        public static string UpdateOctKeyset = @"{{ 
                                                     'keys': [ 
                                                           {{ 
                                                              'k': '{0}',  
                                                              'use': 'sig', 
                                                             'kty': 'oct'
                                                         }}
                                                          ]
                                                }}"; 

        public static string UpdateRSAKeyset = @"{{
                                                     'keys': [
                                                            {{
                                                             'use': 'sig',
                                                             'kty': 'RSA',
                                                             'e': '{0}',    
                                                             'n': '{0}' 
                                                             }}
                                                         ]
                                                }}";

        
        public static string GenerateKey = @"{{
                            'use': 'sig',  'kty': 'RSA',  'nbf': {0},  'exp': {1}
                            }} ";

        public static string UploadSecret = @"{{  'use': 'sig',  'k': '{0}',  'nbf': {1},  'exp': {2} }} ";

        public static string UploadCertificate = @"{{  'key': '{0}' }} ";

        public static string UploadPkcs = @"{{  'key': '{0}',   'password': '{0}' }}";

        static Constants()
        {
            
            CreateKeyset = string.Format(CreateKeyset, KEYSETID_TOKEN);

            UpdateOctKeyset = string.Format(UpdateOctKeyset, SECRET_TOKEN);

            UpdateRSAKeyset = string.Format(UpdateRSAKeyset, SECRET_TOKEN);

            GenerateKey = string.Format(GenerateKey, NBF_TOKEN, EXP_TOKEN);

            UploadSecret = string.Format(UploadSecret, SECRET_TOKEN, NBF_TOKEN, EXP_TOKEN);

            UploadCertificate = string.Format(UploadCertificate, SECRET_TOKEN);

            UploadPkcs = string.Format(UploadPkcs, SECRET_TOKEN);
        }
    }
}
