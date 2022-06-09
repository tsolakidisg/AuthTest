using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using System.Net;
using System.Collections.Specialized;

namespace AuthTest1
{
    public static class Function1
    {
        [FunctionName("Function1")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            var secret = Environment.GetEnvironmentVariable("SecretFromKeyVault", EnvironmentVariableTarget.Process);

            log.LogInformation($"Secret: { secret}");

            var cert = Environment.GetEnvironmentVariable("CertificateFromKeyVault", EnvironmentVariableTarget.Process);
            byte[] certBytes = Convert.FromBase64String(cert);
            var certificate = new X509Certificate2(certBytes, String.Empty,
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
            var signingCredentials = new X509SigningCredentials(certificate, "RS256");

            // jwt header
            var header = new { alg = "RS256" };
            var claimTemplate = new
            {
                iss = "3MVG9KlmwBKoC7U1H3Bwx6cd2AzDjrAMtnEEe2iNjNio374UAIoYw.pT5qnHi5gTCmbrXDTkRRmqCueD94vkN",
                sub = "gtsolakidis@deloitte.gr.integr",
                aud = "https://test.salesforce.com",
                exp = GetExpiryDate(),
                jti = Guid.NewGuid(),
            };

            // encoded header
            var headerSerialized = JsonConvert.SerializeObject(header);
            var headerBytes = Encoding.UTF8.GetBytes(headerSerialized);
            var headerEncoded = ToBase64UrlString(headerBytes);

            // encoded claim template
            var claimSerialized = JsonConvert.SerializeObject(claimTemplate);
            var claimBytes = Encoding.UTF8.GetBytes(claimSerialized);
            var claimEncoded = ToBase64UrlString(claimBytes);

            // input
            var input = headerEncoded + "." + claimEncoded;
            var inputBytes = Encoding.UTF8.GetBytes(input);

            var signature = JwtTokenUtilities.CreateEncodedSignature(input, signingCredentials);
            var jwt = headerEncoded + "." + claimEncoded + "." + signature;
            log.LogInformation("JWT created and signed successfully!");

            var client = new WebClient();
            client.Encoding = Encoding.UTF8;
            var uri = "https://d7q000002cblcua0--integr.my.salesforce.com/services/oauth2/token";
            var content = new NameValueCollection();

            content["assertion"] = jwt;
            content["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer";

            string response = Encoding.UTF8.GetString(client.UploadValues(uri, "POST", content));

            var result = JsonConvert.DeserializeObject<dynamic>(response);

            log.LogInformation($"SUCCESS: {result}");

            return new OkObjectResult(result);
        }

        static int GetExpiryDate()
        {
            var utc0 = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            var currentUtcTime = DateTime.UtcNow;

            var exp = (int)currentUtcTime.AddMinutes(3).Subtract(utc0).TotalSeconds;

            return exp;
        }

        static string ToBase64UrlString(byte[] input)
        {
            return Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
    }
}
