using BitCoinSharp;
using System.Collections;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;
using System.Net;
using UnityEngine;
using ZXing;
using ZXing.QrCode;
using WebSocketSharp;
using BtcPayApi;
using System.Collections.Generic;

/**
 * @author Andy Phillipson
 * @date 9.3.2014
 * 
 * See bitpay.com/api for more information.
 */

namespace BTCPayAPI
{

    public class BTCPayClient
    {
        private const String BITPAY_API_VERSION = "2.0.0";
        private const String BITPAY_PLUGIN_INFO = "BTCPay CSharp Client " + BITPAY_API_VERSION;
        public const String HOST = "";
        private const String BITPAY_URL = "https://"+HOST+"/";

        public const String FACADE_POS = "pos";
        public const String FACADE_MERCHANT = "merchant";
        public const String FACADE_USER = "user";

        private String _serverHost = null;
        private HttpClient _httpClient = null;
        private String _baseUrl = BITPAY_URL;
        private EcKey _ecKey = null;
        private String _identity = "";
        private String _clientName = "";
        private Dictionary<string, string> _tokenCache; // {facade, token}

        private String pairingCode = "";

        /// <summary>
        /// Constructor for use if the keys and SIN are managed by this library.
        /// </summary>
        /// <param name="pairCode">Server driven pairing code from BTCPay server</param>
        /// <param name="clientName">The label for this client.</param>
        /// <param name="envUrl">The target server URL.</param>
        public BTCPayClient(String pairCode="", String serverhost = HOST, String clientName = BITPAY_PLUGIN_INFO)
        {
            if (pairCode == "")
            {
                throw new Exception("Server initiated Pairing code is mandatory.BTCPay->Stores->Settings->Access Token->Create New Token(Pubkey to be blank) ");
            }
            // IgnoreBadCertificates();
            this.pairingCode = pairCode;

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            if (clientName.Equals(BITPAY_PLUGIN_INFO))
            {
                clientName += " on " + System.Environment.MachineName;
            }
            // Eliminate special characters from the client name (used as a token label).  Trim to 60 chars.
            string _clientName = new Regex("[^a-zA-Z0-9_ ]").Replace(clientName, "_");
            if (_clientName.Length > 60)
            {
                _clientName = _clientName.Substring(0, 60);
            }
            _serverHost = serverhost;
            _baseUrl = "https://" + _serverHost + "/"; 
    	    _httpClient = new HttpClient();
            _httpClient.BaseAddress = new Uri(_baseUrl);

            this.initKeys();//Private Key load or create anew
            this.deriveIdentity();//compute SIN number from pubkey
            this.tryGetAccessTokens();

            // Is this client already authorized to use the POS facade?
            if (!clientIsAuthorized(BTCPayClient.FACADE_POS))
            {
                // Get POS facade authorization.
                authorizeClient(pairingCode);
            }

        }
        
        /// <summary>
        /// Return the identity of this client.
        /// </summary>
        public String Identity
        {
            get { return _identity; }
        }

        /// <summary>
        /// Authorize (pair) this client with the server using the specified pairing code.
        /// </summary>
        /// <param name="pairingCode">A code obtained from the server; typically from bitpay.com/api-tokens.</param>
        public void authorizeClient(String pairingCode)
        {
            Token token = new Token();
            token.Id = _identity;
            token.Guid = Guid.NewGuid().ToString();
            token.PairingCode = pairingCode;
            token.Label = _clientName;
            String json = JsonConvert.SerializeObject(token);
            HttpResponseMessage response = this.post("tokens", json);
            List<Token> tokens = JsonConvert.DeserializeObject<List<Token>>(this.responseToJsonString(response));
            foreach (Token t in tokens)
            {
                Debug.Log("t.Facade, t.Value " + t.Facade +" "+ t.Value);
                cacheToken(t.Facade, t.Value);
            }
        }

        /// <summary>
        /// Specified whether the client has authorization (a token) for the specified facade.
        /// </summary>
        /// <param name="facade">The facade name for which authorization is tested.</param>
        /// <returns></returns>
        public bool clientIsAuthorized(String facade)
        {
            return _tokenCache.ContainsKey(facade);
        }

        /// <summary>
        /// Create an invoice using the specified facade.
        /// </summary>
        /// <param name="invoice">An invoice request object.</param>
        /// <returns>A new invoice object returned from the server.</returns>
        public Invoice createInvoice(Invoice invoice, String facade = FACADE_POS)
        {
            invoice.Token = this.getAccessToken(facade);//get token by facade type
            invoice.Guid = Guid.NewGuid().ToString();
            String json = JsonConvert.SerializeObject(invoice);
            HttpResponseMessage response = this.postWithSignature("invoices", json);
            String invoiceStr = this.responseToJsonString(response);
            JsonConvert.PopulateObject(this.responseToJsonString(response), invoice);

            // Track the token for this invoice
            cacheToken(invoice.Id, invoice.Token);

            return invoice;
        }

        /// <summary>
        /// Retrieve an invoice by id and token.
        /// </summary>
        /// <param name="invoiceId">The id of the requested invoice.</param>
        /// <returns>The invoice object retrieved from the server.</returns>
        public Invoice getInvoice(String invoiceId, String facade = FACADE_POS)
        {
            // Provide the merchant token when the merchant facade is being used.
            // GET/invoices expects the merchant token and not the merchant/invoice token.
            Dictionary<string, string> parameters = null;
//            if (facade == FACADE_MERCHANT)
            {
                try
                {
                    parameters = new Dictionary<string, string>();
//                    parameters.Add("token", getAccessToken(FACADE_MERCHANT));
                    parameters.Add("token", getAccessToken(facade));
                }
                catch (BitPayException)
                {
                    // No token for invoice.
                    parameters = null;
                }
            }
            HttpResponseMessage response = this.get("invoices/" + invoiceId, parameters);
            return JsonConvert.DeserializeObject<Invoice>(this.responseToJsonString(response));
        }
        /// <summary>
        /// Retrieve a list of invoices by date range using the merchant facade.
        /// </summary>
        /// <param name="dateStart">The start date for the query.</param>
        /// <param name="dateEnd">The end date for the query.</param>
        /// <returns>A list of invoice objects retrieved from the server.</returns>
        public List<Invoice> getInvoices(DateTime dateStart, DateTime dateEnd)
        {
            Dictionary<String, String> parameters = this.getParams();
            parameters.Add("token", this.getAccessToken(FACADE_MERCHANT));
            parameters.Add("dateStart", dateStart.ToShortDateString());
            parameters.Add("dateEnd", dateEnd.ToShortDateString());
            HttpResponseMessage response = this.get("invoices", parameters);
            return JsonConvert.DeserializeObject<List<Invoice>>(this.responseToJsonString(response));
        }

        /// <summary>
        /// Retrieve the exchange rate table using the public facade.
        /// </summary>
        /// <returns>The rate table as an object retrieved from the server.</returns>
        public Rates getRates()
        {
            HttpResponseMessage response = this.get("rates");
            List<Rate> rates = JsonConvert.DeserializeObject<List<Rate>>(this.responseToJsonString(response));
            return new Rates(rates, this);
        }

        /// <summary>
        /// Retrieves a summary of the specified settlement.
        /// </summary>
        /// <param name="settlementId">Settlement Id</param>
        /// <returns>A BitPay Settlement object.</returns>
        public Settlement getSettlement(string settlementId)
        {
            var parameters = new Dictionary<string, string>
            {
                { "token", getAccessToken(FACADE_MERCHANT) }
            };

            HttpResponseMessage response = get($"settlements/{settlementId}", parameters);
            return JsonConvert.DeserializeObject<Settlement>(responseToJsonString(response));
        }

        public IEnumerator subscribeInvoice(string invoiceId, Action<Invoice> actionOnInvoice, MonoBehaviour mb)
        {
            CoroutineWithData cd = new CoroutineWithData(mb, SubscribeInvoiceCoroutine(invoiceId));
            yield return cd.coroutine;

            Debug.Log("BtcPayUnity: Invoice Result is " + cd.result);

            Invoice resultInv = (Invoice)cd.result;
            actionOnInvoice(resultInv);
        }

        private IEnumerator SubscribeInvoiceCoroutine(string invoiceId)
        {
            Invoice inv = null;
            using (var ws = new WebSocket("wss://" + _serverHost + "/i/" + invoiceId + "/status/ws"))
            {
                ws.SslConfiguration.EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12;
                ws.OnMessage += (sender, e) =>
                {
                    Debug.Log("BtcPayUnity:WS Message: " + e.Data);
                    //Get Invoice 
                    //                inv = getInvoice(invoiceId, BTCPay.FACADE_MERCHANT);
                    inv = getInvoice(invoiceId);//Default Pos facade
                    Debug.Log("BtcPayUnity:Got invoice : " + inv.Status);
                    ws.Close();
                };
                ws.OnClose += (sender, e) =>
                {
                    Debug.Log("BtcPayUnity:WS Closed: " + e.Code);
                };
                ws.OnError += (sender, e) =>
                {
                    Debug.Log("BtcPayUnity:WS Err: " + e.Exception);
                };
                ws.OnOpen += (sender, e) =>
                  Debug.Log("BtcPayUnity:WS Opened.");

                ws.Connect();

                //Wait connection is closed when invoice is gotten or exception
                while (ws.IsAlive)
                {
                    //Thread.Sleep(500);
                    yield return new WaitForSeconds(0.5f);
                    Debug.Log("BtcPayUnity:Websocket Sleep/Yield 500ms.");
                }
            }//Auto Close websocket
            yield return inv;
        }



        //public void printws()
        //{
        //    Debug.Log("Number of ws:" + _wsMap.Count);
        //    if(_wsMap.Count> 0)
        //    {
        //        foreach(var entry in _wsMap)
        //        {
        //            Debug.Log("ws status:" + entry.Value.IsAlive);
        //        }
        //    }
        //}

        private static Color32[] Encode(string textForEncoding,
          int width, int height)
        {
            var writer = new BarcodeWriter
            {
                Format = BarcodeFormat.QR_CODE,
                Options = new QrCodeEncodingOptions
                {
                    Height = height,
                    Width = width
                }
            };
            return writer.Write(textForEncoding);
        }
        public Texture2D generateQR(string text)
        {
            var encoded = new Texture2D(384, 384);
            var color32 = Encode(text, encoded.width, encoded.height);
            encoded.SetPixels32(color32);
            encoded.Apply();
            return encoded;
        }


        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        private void initKeys()
        {
            if (KeyUtils.privateKeyExists())
            {
                _ecKey = KeyUtils.loadEcKey();

                // Alternatively, load your private key from a location you specify.
                //_ecKey = KeyUtils.createEcKeyFromHexStringFile("C:\\Users\\Andy\\Documents\\private-key.txt");
            }
            else
            {
                _ecKey = KeyUtils.createEcKey();
                KeyUtils.saveEcKey(_ecKey);
            }
        }

        private void deriveIdentity()
        {
            // Identity in this implementation is defined to be the SIN.
            _identity = KeyUtils.deriveSIN(_ecKey);
        }

        private Dictionary<string, string> responseToTokenCache(HttpResponseMessage response)
        {
            // The response is expected to be an array of key/value pairs (facade name = token).
            dynamic obj = JsonConvert.DeserializeObject(responseToJsonString(response));

//            if (obj.GetType() != typeof(DynamicJsonArray))
            if (obj.GetType() != typeof(JArray))//TODO Fix the Type CHECK
            {
                throw new BitPayException("Error: Response to GET /tokens is expected to be an array, got a " + obj.GetType());
            }
            try
            {
//                for (int i = 0; i < obj.Count; i++)
                foreach(var kc in obj.Children())
                {
//                    Dictionary<string, object>.KeyCollection kc = obj[i].GetDynamicMemberNames();
                    if (kc.Count > 1)
                    {
                        throw new BitPayException("Error: Size of Token object is unexpected.  Expected one entry, got " + kc.Count + " entries.");
                    }
                    foreach (var entry in kc)
                    {
                        if (!_tokenCache.ContainsKey(entry.Name))
                        {
                            cacheToken(entry.Name, entry.Value.Value);
                        }
                    }
                }
            }
            catch (BitPayException ex)
            {
                throw new BitPayException("Error: " + ex.ToString());
            }
            catch (Exception ex)
            {
                throw new BitPayException("Error: response to GET /tokens could not be parsed - " + ex.ToString());
            }
            return _tokenCache;
        }

        private void clearAccessTokenCache() {
            _tokenCache = new Dictionary<string, string>();
        }

        private void cacheToken(String key, String token)
        {
            _tokenCache.Add(key, token);
        }

        private bool tryGetAccessTokens()
        {
            // Attempt to get access tokens for this client identity.
            try
            {
                // Success if at least one access token was returned.
                return this.getAccessTokens() > 0;
            }
            catch (BitPayException ex)
            {
                // If the error states that the identity is invalid then this client has not been
                // registered with the BitPay account.
                if (ex.getMessage().Contains("Unauthorized sin"))
                {
                    this.clearAccessTokenCache();
                    return false;
                }
                else
                {
                    // Propagate all other errors.
                    throw ex;
                }
            }
        }

        private int getAccessTokens()
        {
            this.clearAccessTokenCache();//empty token map
            Dictionary<String, String> parameters = this.getParams();
            HttpResponseMessage response = this.get("tokens", parameters);
            _tokenCache = responseToTokenCache(response);
            return _tokenCache.Count;
        }

        private String getAccessToken(String key)
        {
            if (!_tokenCache.ContainsKey(key))
            {
                throw new BitPayException("Error: You do not have access to facade: " + key);
            }
            return _tokenCache[key];
        }

        private Dictionary<string, string> getParams()
        {
            Dictionary<string, string> parameters = new Dictionary<string, string>();
            return parameters;
        }

        private HttpResponseMessage get(String uri, Dictionary<string, string> parameters = null)
        {
            try
            {
                String fullURL = _baseUrl + uri;
                _httpClient.DefaultRequestHeaders.Clear();
                _httpClient.DefaultRequestHeaders.Add("x-accept-version", BITPAY_API_VERSION);
                _httpClient.DefaultRequestHeaders.Add("x-bitpay-plugin-info", BITPAY_PLUGIN_INFO);
                if (parameters != null)
                {
                    fullURL += "?";
                    foreach (KeyValuePair<string, string> entry in parameters)
                    {
                        fullURL += entry.Key + "=" + entry.Value + "&";
                    }
                    fullURL = fullURL.Substring(0, fullURL.Length - 1);
                    String signature = KeyUtils.sign(_ecKey, fullURL);
                    _httpClient.DefaultRequestHeaders.Add("x-signature", signature);
                    _httpClient.DefaultRequestHeaders.Add("x-identity", KeyUtils.bytesToHex(_ecKey.PubKey));
                }

                var result = _httpClient.GetAsync(fullURL).Result;
                return result;
            }
            catch (Exception ex)
            {
                throw new BitPayException("Error: " + ex.ToString());
            }
        }

        private HttpResponseMessage delete(String uri, Dictionary<string, string> parameters = null)
        {
            try
            {
                String fullURL = _baseUrl + uri;
                _httpClient.DefaultRequestHeaders.Clear();
                _httpClient.DefaultRequestHeaders.Add("x-accept-version", BITPAY_API_VERSION);
                _httpClient.DefaultRequestHeaders.Add("x-bitpay-plugin-info", BITPAY_PLUGIN_INFO);

                if (parameters != null)
                {
                    fullURL += "?";
                    foreach (KeyValuePair<string, string> entry in parameters)
                    {
                        fullURL += entry.Key + "=" + entry.Value + "&";
                    }
                    fullURL = fullURL.Substring(0, fullURL.Length - 1);
                    String signature = KeyUtils.sign(_ecKey, fullURL);
                    _httpClient.DefaultRequestHeaders.Add("x-signature", signature);
                    _httpClient.DefaultRequestHeaders.Add("x-identity", KeyUtils.bytesToHex(_ecKey.PubKey));
                }

                var result = _httpClient.DeleteAsync(fullURL).Result;
                return result;
            }
            catch (Exception ex)
            {
                throw new BitPayException("Error: " + ex.ToString());
            }
        }

        private HttpResponseMessage postWithSignature(String uri, String json)
        {
            return this.post(uri, json, true);
        }

        private HttpResponseMessage post(String uri, String json, bool signatureRequired = false)
        {
            try
            {
                var bodyContent = new StringContent(this.unicodeToAscii(json));
                _httpClient.DefaultRequestHeaders.Clear();
                _httpClient.DefaultRequestHeaders.Add("x-accept-version", BITPAY_API_VERSION);
                _httpClient.DefaultRequestHeaders.Add("x-bitpay-plugin-info", BITPAY_PLUGIN_INFO);
                bodyContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                if (signatureRequired)
                {
                    String signature = KeyUtils.sign(_ecKey, _baseUrl + uri + json);
                    _httpClient.DefaultRequestHeaders.Add("x-signature", signature);
                    _httpClient.DefaultRequestHeaders.Add("x-identity", KeyUtils.bytesToHex(_ecKey.PubKey));
                }
                var result = _httpClient.PostAsync(uri, bodyContent).Result;
                return result;
            }
            catch (Exception ex)
            {
                throw new BitPayException("Error: " + ex.ToString());
            }
        }

        private String responseToJsonString(HttpResponseMessage response)
        {
            if (response == null)
            {
                throw new BitPayException("Error: HTTP response is null");
            }

            // Get the response as a dynamic object for detecting possible error(s) or data object.
            // An error(s) object raises an exception.
            // A data object has its content extracted (throw away the data wrapper object).
            String responseString = response.Content.ReadAsStringAsync().Result;
            Debug.Log(" Json Response Detail:" + responseString);

            dynamic obj = JsonConvert.DeserializeObject(responseString);

            // Check for error response.
            if (dynamicObjectHasProperty(obj, "error"))
            {
                throw new BitPayException("Error: " + obj.error);
            }
            if (dynamicObjectHasProperty(obj, "errors"))
            {
                String message = "Multiple errors:";
                foreach (var errorItem in obj.errors)
                {
                    message += "\n" + errorItem.error + " " + errorItem.param;
                }
                throw new BitPayException(message);
            }

            // Check for and exclude a "data" object from the response.
            if (dynamicObjectHasProperty(obj, "data"))
            {
                responseString = JObject.Parse(responseString).SelectToken("data").ToString();
            }
            return Regex.Replace(responseString, @"\r\n", "");
        }

        private static bool dynamicObjectHasProperty(dynamic obj, string name)
        {
            bool result = false;

            //            if (obj.GetType() == typeof(DynamicJsonObject))
            if (obj.GetType() == typeof(JObject))//TODO Fix the Type CHECK
            {
                var dataValue = obj["data"];
                var errorValue = obj[name];
                result = errorValue != null;
                //Dictionary<string, object>.KeyCollection kc = obj.GetDynamicMemberNames();
                //result = kc.Contains(name);
            }
            return result;
        }

        private void IgnoreBadCertificates()
        {
            System.Net.ServicePointManager.ServerCertificateValidationCallback =
                new System.Net.Security.RemoteCertificateValidationCallback(AcceptAllCertifications);
        }

        private bool AcceptAllCertifications(
            object sender,
            System.Security.Cryptography.X509Certificates.X509Certificate certification,
            System.Security.Cryptography.X509Certificates.X509Chain chain,
            System.Net.Security.SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

        private String unicodeToAscii(String json)
        {
            byte[] unicodeBytes = Encoding.Unicode.GetBytes(json);
            byte[] asciiBytes = Encoding.Convert(Encoding.Unicode, Encoding.ASCII, unicodeBytes);
            char[] asciiChars = new char[Encoding.ASCII.GetCharCount(asciiBytes, 0, asciiBytes.Length)];
            Encoding.ASCII.GetChars(asciiBytes, 0, asciiBytes.Length, asciiChars, 0);
            return new String(asciiChars);
        }

    }

}
