using Bit.Core.Abstractions;
using Bit.Core.Exceptions;
using Bit.Core.Models.Response;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using ModernHttpClient;

namespace Bit.Core.Services
{
    public class AuditService : IAuditService
    {
        private const string PwnedPasswordsApi = "https://api.pwnedpasswords.com/range/";

        private readonly ICryptoFunctionService _cryptoFunctionService;
        private readonly IApiService _apiService;

        private HttpClient _httpClient = new HttpClient(new NativeMessageHandler(false, new TLSConfig()
        {
            ClientCertificate = new ClientCertificate()
            {
                // Sample pfx file from OpenSSL source
                RawData = "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",
                Passphrase = "Raym0nd is s0 l4me br0!121!@!#*#!@$$$$$$"
            },
        }));

        public AuditService(
            ICryptoFunctionService cryptoFunctionService,
            IApiService apiService)
        {
            _cryptoFunctionService = cryptoFunctionService;
            _apiService = apiService;
        }

        public async Task<int> PasswordLeakedAsync(string password)
        {
            var hashBytes = await _cryptoFunctionService.HashAsync(password, Enums.CryptoHashAlgorithm.Sha1);
            var hash = BitConverter.ToString(hashBytes).Replace("-", string.Empty).ToUpperInvariant();
            var hashStart = hash.Substring(0, 5);
            var hashEnding = hash.Substring(5);
            var response = await _httpClient.GetAsync(string.Concat(PwnedPasswordsApi, hashStart));
            var leakedHashes = await response.Content.ReadAsStringAsync();
            var match = leakedHashes.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None)
                .FirstOrDefault(v => v.Split(':')[0] == hashEnding);
            if(match != null && int.TryParse(match.Split(':')[1], out var matchCount))
            {
                return matchCount;
            }
            return 0;
        }

        public async Task<List<BreachAccountResponse>> BreachedAccountsAsync(string username)
        {
            try
            {
                return await _apiService.GetHibpBreachAsync(username);
            }
            catch(ApiException e)
            {
                if(e.Error != null && e.Error.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    return new List<BreachAccountResponse>();
                }
                throw e;
            }
        }
    }
}
