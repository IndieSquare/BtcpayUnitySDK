
using System.Collections;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Text;
using System.Text.RegularExpressions;
using UnityEngine;
using UnityEngine.Networking;
using System.Collections.Generic;
using NBitcoin;
using NBitcoin.Crypto;
using System.Security.Cryptography;
using ZXing;
using ZXing.QrCode;
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

        public const String FACADE_MERCHANT = "merchant";
        //public const String FACADE_USER = "user";

        private String _serverHost = null;
        
        private String _baseUrl = "";
        private Key _ecKey = null;
        private String _identity = "";
        private String _clientName = "";
        private Dictionary<string, string> _tokenCache; // {facade, token}

        private String _pairingCode = "";
        private MonoBehaviour _owner = null;

        /// <summary>
        /// Constructor for use if the keys and SIN are managed by this library.
        /// </summary>
        /// <param name="pairCode">Server driven pairing code from BTCPay server</param>
        /// <param name="clientName">The label for this client.</param>
        /// <param name="envUrl">The target server URL.</param>
        public BTCPayClient(MonoBehaviour owner,String pairCode, String serverhost, String clientName = BITPAY_PLUGIN_INFO)
        {
            if (!owner)
            {
                throw new Exception("Server initiated MonoBehavior is mandatory.");
            }
            _owner = owner;

            if (string.IsNullOrEmpty(pairCode))
            {
                throw new Exception("Server initiated Pairing code is mandatory.BTCPay->Stores->Settings->Access Token->Create New Token(Pubkey to be blank) ");
            }
            // IgnoreBadCertificates();
            _pairingCode = pairCode;

            if (clientName.Equals(BITPAY_PLUGIN_INFO))
            {
                clientName += " on " + System.Environment.MachineName;
            }
            // Eliminate special characters from the client name (used as a token label).  Trim to 60 chars.
            _clientName = new Regex("[^a-zA-Z0-9_ ]").Replace(clientName, "_");
            if (_clientName.Length > 60)
            {
                _clientName = _clientName.Substring(0, 60);
            }

            if (string.IsNullOrEmpty(serverhost))
            {
                throw new Exception("BTCpay server hostname is mandatory.");
            }
            _serverHost = serverhost;
            _baseUrl = "https://" + _serverHost + "/";
            Debug.Log("in Constructor:_baseUrl="+ _baseUrl);

        }

        public IEnumerator initialize()
        {
            initKeys();//Private Key load or create anew
            deriveIdentity();//compute SIN number from pubkey
            yield return tryGetAccessTokens();

            // Is this client already authorized to use the MERCHANT facade?
            if (!clientIsAuthorized(BTCPayClient.FACADE_MERCHANT))
            {
                Debug.Log("initialize():client Not authorized yet.Getting authorized.");
                // Get MERCHANT facade authorization.
                yield return authorizeClient(_pairingCode);
            }
            else
            {
                Debug.Log("initialize():client Already Authorized.");
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
        public IEnumerator authorizeClient( String pairingCode)
        {
            Token token = new Token();
            token.Id = _identity;
            token.Guid = Guid.NewGuid().ToString();
            token.PairingCode = pairingCode;
            token.Label = _clientName;
            String json = JsonConvert.SerializeObject(token);

            CoroutineWithData cd = new CoroutineWithData(_owner, post("tokens", json));
            yield return cd.coroutine;

            string tokenStr = (string)cd.result;

            tokenStr = responseToJsonString(tokenStr);
            Debug.Log("authorizeClient(): tokenStr:" + tokenStr);

            cacheTokens(tokenStr);
        }

        private void cacheTokens(string responseStr)
        {
            Debug.Log("cacheTokens(): Got authorized tokens with "+responseStr);

            List<Token> tokens = JsonConvert.DeserializeObject<List<Token>>(responseStr);
            foreach (Token t in tokens)
            {
                Debug.Log("t.Facade, t.Value " + t.Facade + " " + t.Value);
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
        public IEnumerator createInvoice(Invoice invoice, Action<Invoice> invoiceAction, String facade = FACADE_MERCHANT)
        {
            Debug.Log("createInvoice(): Curr"+invoice.Currency+" Price:"+invoice.Price +" "+invoice.BuyerEmail+" "+invoice.ItemDesc);

            invoice.Token = this.getAccessToken(facade);//get token by facade type
            invoice.Guid = Guid.NewGuid().ToString();
            String json = JsonConvert.SerializeObject(invoice);
            Debug.Log("createInvoice(): About to post an initial Invoice " + json);

            CoroutineWithData cd = new CoroutineWithData(_owner, post("invoices", json,true));
            yield return cd.coroutine;
            string responseStr = (string)cd.result;
            Debug.Log("createInvoice():  response:" + responseStr);

            JsonConvert.PopulateObject(this.responseToJsonString(responseStr), invoice);
            Debug.Log("createInvoice():  responsejson to Invoice Object done token1:id=" + invoice.Id + " token=" + invoice.Token + " json=" + JsonConvert.SerializeObject(invoice)+ " toString:"+invoice.ToString());
            invoice = JsonConvert.DeserializeObject<Invoice>(this.responseToJsonString(responseStr));
            Debug.Log("createInvoice():  responsejson to Invoice Object done token2:id=" + invoice.Id + " token=" + invoice.Token + " json="+ JsonConvert.SerializeObject(invoice) + " toString:" + invoice.ToString());

            // Track the token for this invoice
            cacheToken(invoice.Id, invoice.Token);
            //
            Debug.Log("createInvoice():  Taking InvoiceAction callback BEFORE");
            invoiceAction(invoice);
            Debug.Log("createInvoice():  Taking InvoiceAction callback AFTER");
        }

        /// <summary>
        /// Retrieve an invoice by id and token.
        /// </summary>
        /// <param name="invoiceId">The id of the requested invoice.</param>
        /// <returns>The invoice object retrieved from the server.</returns>
        public IEnumerator getInvoice(String invoiceId, Action<Invoice> invoiceAction, String facade = FACADE_MERCHANT)
        {
            // Provide the merchant token when the merchant facade is being used.
            // GET/invoices expects the merchant token and not the merchant/invoice token.
            Dictionary<string, string> parameters = null;
//            if (facade == FACADE_MERCHANT)
//            {
                try
                {
                    parameters = new Dictionary<string, string>();
//                    parameters.Add("token", getAccessToken(FACADE_MERCHANT));
                    parameters.Add("token", getAccessToken(facade));
                    Debug.Log("getInvoice():  add param: token="+ getAccessToken(facade));

            }
            catch (BitPayException)
                {
                // No token for invoice.
                Debug.Log("getInvoice():  add param: NO TOKEN for "+ facade);
                parameters = null;
                }
 //           }
            CoroutineWithData cd = new CoroutineWithData(_owner, get("invoices/" + invoiceId, parameters));
            yield return cd.coroutine;
            String invoiceStr = (string) cd.result;
            Debug.Log("getInvoice():  Invoice Json :" + invoiceStr);
            Invoice invoice = JsonConvert.DeserializeObject<Invoice>(responseToJsonString(invoiceStr));

            invoiceAction(invoice);

        }
        /// <summary>
        /// Retrieve the exchange rate table using the public facade.
        /// </summary>
        /// <returns>The rate table as an object retrieved from the server.</returns>
        public IEnumerator getRates(Action<Rates> ratesAction)
        {
            CoroutineWithData cd = new CoroutineWithData(_owner, get("rates"));
            yield return cd.coroutine;
            String ratesStr = (string)cd.result;

            List<Rate> rates = JsonConvert.DeserializeObject<List<Rate>>(ratesStr);
            ratesAction(new Rates(rates, this));
        }

        public IEnumerator listenInvoice(string invoiceId, Action<Invoice> actionOnInvoice)
        {
            Debug.Log("listenInvoice(): websocket start : invoiceId=" + invoiceId);
            WebSocket w = new WebSocket(new Uri("ws://echo.websocket.org"));
            yield return w.Connect();
            w.SendString("Hi there");
            int i = 0;
            while (true)
            {
                string reply = w.RecvString();
                if (reply != null)
                {
                    Debug.Log("Received: " + reply);
                    w.SendString("Hi there" + i++);
                }
                if (w.error != null)
                {
                    Debug.LogError("Error: " + w.error);
                    break;
                }
                yield return 0;
            }
            w.Close();
        }
        //public IEnumerator subscribeInvoice(string invoiceId, Action<Invoice> actionOnInvoice)
        //{
        //    CoroutineWithData cd = new CoroutineWithData(_owner, SubscribeInvoiceCoroutine(invoiceId));
        //    yield return cd.coroutine;

        //    Debug.Log("BtcPayUnity: Invoice Result is " + cd.result);

        //    Invoice resultInv = (Invoice)cd.result;
        //    actionOnInvoice(resultInv);
        //}

        public IEnumerator SubscribeInvoiceCoroutine(string invoiceId, Action<Invoice> actionOnInvoice)
        {
            //WebSocket  loop
            Debug.Log("SubscribeInvoiceCoroutine(): websocket start : invoiceId=" + invoiceId);
            WebSocket ws = new WebSocket(new Uri("wss://" + _serverHost + "/i/" + invoiceId + "/status/ws"));
            Debug.Log("SubscribeInvoiceCoroutine(): websocket before connection : WebSocket Platform=" + ws.GetPlatform());
            yield return ws.Connect();
            Debug.Log("SubscribeInvoiceCoroutine(): websocket connected : invoiceId=" + invoiceId +" ws:"+ws.ToString());
            while (true)
            {
//                Debug.Log("SubscribeInvoiceCoroutine(): Websocket Loop ");
                string reply = ws.RecvString();
//                Debug.Log("SubscribeInvoiceCoroutine(): Websocket Loop after s.RecvString() ");
                if (reply != null)
                {
                  //  Debug.Log("SubscribeInvoiceCoroutine(): Websocket Received: " + reply);
                    yield return getInvoice(invoiceId, actionOnInvoice);
                    break;
                }
                else
                {
                 //   Debug.Log("SubscribeInvoiceCoroutine(): Websocket Received:  null" );
                }

                if (ws.error != null)
                {
                    Debug.Log("SubscribeInvoiceCoroutine(): Websocket Error: " + ws.error);
                    break;
                }
                yield return 0;
            }
            ws.Close();
            Debug.Log("SubscribeInvoiceCoroutine(): websocket closed : invoiceId=" + invoiceId);
        }

        //        private IEnumerator SubscribeInvoiceCoroutine(string invoiceId, Action<Invoice> actionOnInvoice)
        //{
        //    Invoice inv = null;
        //    using (var ws = new WebSocket("wss://" + _serverHost + "/i/" + invoiceId + "/status/ws"))
        //    {
        //        ws.SslConfiguration.EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12;
        //        ws.OnMessage += (sender, e) =>
        //        {
        //            Debug.Log("BtcPayUnity:WS Message: " + e.Data);
        //            //Get Invoice 
        //            //                inv = getInvoice(invoiceId, BTCPay.FACADE_MERCHANT);
        //            getInvoice(invoiceId, actionOnInvoice);//Default MERCHANT facade
        //            Debug.Log("BtcPayUnity:Got invoice : " + inv.Status);
        //            ws.Close();
        //        };
        //        ws.OnClose += (sender, e) =>
        //        {
        //            Debug.Log("BtcPayUnity:WS Closed: " + e.Code);
        //        };
        //        ws.OnError += (sender, e) =>
        //        {
        //            Debug.Log("BtcPayUnity:WS Err: " + e.Exception);
        //        };
        //        ws.OnOpen += (sender, e) =>
        //          Debug.Log("BtcPayUnity:WS Opened.");

        //        ws.Connect();

        //        //Wait connection is closed when invoice is gotten or exception
        //        while (ws.IsAlive)
        //        {
        //            //Thread.Sleep(500);
        //            yield return new WaitForSeconds(0.5f);
        //            Debug.Log("BtcPayUnity:Websocket Sleep/Yield 500ms.");
        //        }
        //    }//Auto Close websocket
        //     //            yield return inv;
        //}
        //private IEnumerator SubscribeInvoiceCoroutine(string invoiceId, Action<Invoice> actionOnInvoice)
        //{
        //    Invoice inv = null;
        //    using (var ws = new WebSocket("wss://" + _serverHost + "/i/" + invoiceId + "/status/ws"))
        //    {
        //        ws.SslConfiguration.EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12;
        //        ws.OnMessage += (sender, e) =>
        //        {
        //            Debug.Log("BtcPayUnity:WS Message: " + e.Data);
        //            //Get Invoice 
        //            //                inv = getInvoice(invoiceId, BTCPay.FACADE_MERCHANT);
        //            getInvoice(invoiceId, actionOnInvoice);//Default MERCHANT facade
        //            Debug.Log("BtcPayUnity:Got invoice : " + inv.Status);
        //            ws.Close();
        //        };
        //        ws.OnClose += (sender, e) =>
        //        {
        //            Debug.Log("BtcPayUnity:WS Closed: " + e.Code);
        //        };
        //        ws.OnError += (sender, e) =>
        //        {
        //            Debug.Log("BtcPayUnity:WS Err: " + e.Exception);
        //        };
        //        ws.OnOpen += (sender, e) =>
        //          Debug.Log("BtcPayUnity:WS Opened.");

        //        ws.Connect();

        //        //Wait connection is closed when invoice is gotten or exception
        //        while (ws.IsAlive)
        //        {
        //            //Thread.Sleep(500);
        //            yield return new WaitForSeconds(0.5f);
        //            Debug.Log("BtcPayUnity:Websocket Sleep/Yield 500ms.");
        //        }
        //    }//Auto Close websocket
        //     //            yield return inv;
        //}



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
            Debug.Log("generateQR():generateing Qr for text: " + text);

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


            if (ResourcesDataAccess.FileExists())//load from storage
            {
                Debug.Log("initKeys():privateKeyExists loading eckey");
                //                _ecKey = KeyUtils.loadEcKey();
                _ecKey = KeyUtils.loadNBEcKey();

                // Alternatively, load your private key from a location you specify.
                //_ecKey = KeyUtils.createEcKeyFromHexStringFile("C:\\Users\\Andy\\Documents\\private-key.txt");
            }
            else//create a new private key and store
            {
                Debug.Log("initKeys(): Not privateKeyExists creating eckey");

                //string privHexStr2 = "f356e8785923053e46422ad2c22fcb4f03f2cd0e6e33265bac16e314a7c26684";  //0.hard coded privkey
                //byte[] bytes2 = KeyUtils.hexToBytes(privHexStr2);
                //_ecKey = new Key(bytes2, -1, false)

                //                _ecKey = KeyUtils.createEcKey();      //1.old ECkey
                _ecKey = KeyUtils.createNBEcKey();      //2.Nbitcoin eckey
                byte[] priv = _ecKey.ToBytes();
                //Debug.Log("initKeys(): ecKey:" + KeyUtils.bytesToHex(priv));
                KeyUtils.saveEcKey(_ecKey);           //3.save geenrated one
            }
            Debug.Log("initKeys(): End");
        }

        private void deriveIdentity()
        {
            // Identity in this implementation is defined to be the SIN.
            _identity = KeyUtils.deriveSIN(_ecKey);
            Debug.Log("deriveIdentity(): identity is derived:"+_identity);
        }

        private Dictionary<string, string> responseToTokenCache(string responseStr)
        {
            // The response is expected to be an array of key/value pairs (facade name = token).
            //            dynamic obj = JsonConvert.DeserializeObject(responseToJsonString(response));
            //sample response is, {"data":[{"MERCHANT":"G4AcnWpGtMDw2p1Ci1h1ommxUs4GJdzurbKFdLqCyLEv"}]}
            Debug.Log("responseToTokenCache():responseStr is " + responseStr);

//            dynamic obj = JsonConvert.DeserializeObject(responseToJsonString(responseStr));
            List<Dictionary<string, string>> obj = JsonConvert.DeserializeObject<List<Dictionary<string, string>>>(responseToJsonString(responseStr));

            //            if (obj.GetType() != typeof(DynamicJsonArray))
            //if (obj.GetType() != typeof(JArray))//TODO Fix the Type CHECK
            //{
            //    Debug.Log("Error: Response to GET /tokens is expected to be an array, got a " + obj.GetType());
            //    throw new BitPayException("Error: Response to GET /tokens is expected to be an array, got a " + obj.GetType());
            //}
            try
            {
                foreach(var kc in obj)//each element of list
                {
//                    Dictionary<string, object>.KeyCollection kc = obj[i].GetDynamicMemberNames();
                    if (kc.Count > 1)
                    {
                        throw new BitPayException("Error: Size of Token object is unexpected.  Expected one entry, got " + kc.Count + " entries.");
                    }
                    foreach (var entry in kc) //each map
                    {
                        if (!_tokenCache.ContainsKey(entry.Key))
                        {
                            cacheToken(entry.Key, entry.Value);
                        }
                    }
                }
            }
            catch (BitPayException ex)
            {
                Debug.Log("BitPayException Error: "+ ex.ToString());
                throw new BitPayException("Error: " + ex.ToString());
            }
            catch (Exception ex)
            {
                Debug.Log("Error: response to GET /tokens could not be parsed - " + ex.ToString());
                throw new BitPayException("Error: response to GET /tokens could not be parsed - " + ex.ToString());
            }
            return _tokenCache;
        }

        private void clearAccessTokenCache() {
            _tokenCache = new Dictionary<string, string>();
        }

        private void cacheToken(String key, String token)
        {

            Debug.Log("cacheToken():key:" + key+" value:"+token );
            _tokenCache.Add(key, token);
            Debug.Log("cacheToken():token is stored in cache");
        }

        private IEnumerator tryGetAccessTokens()
        {
            // Attempt to get access tokens for this client identity.
            //try
            //{
                // Success if at least one access token was returned.
                yield return this.getAccessTokens();
            //}
            //catch (BitPayException ex)
            //{
            //    // If the error states that the identity is invalid then this client has not been
            //    // registered with the BitPay account.
            //    if (ex.getMessage().Contains("Unauthorized sin"))
            //    {
            //        this.clearAccessTokenCache();
            //        yield return false;
            //    }
            //    else
            //    {
            //        // Propagate all other errors.
            //        throw ex;
            //    }
            //}
        }

        private IEnumerator getAccessTokens()
        {
            this.clearAccessTokenCache();//empty token map
            Dictionary<String, String> parameters = this.getParams();

            //yield return this.get("tokens", parameters);
            //_tokenCache = responseToTokenCache(response);

            CoroutineWithData cd = new CoroutineWithData(_owner, get("tokens", parameters));
            yield return cd.coroutine;
            string tokensStr = (string)cd.result;
            Debug.Log("getAccessTokens() tokensStr: " + tokensStr);
            _tokenCache = responseToTokenCache(tokensStr);

            yield return _tokenCache.Count;
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

        private IEnumerator get(String uri, Dictionary<string, string> parameters = null)
        {
            String fullURL = _baseUrl + uri;
            Debug.Log("get() is called with "+fullURL);
            Debug.Log("get() is called parameters:" + parameters.Count);

            if (parameters != null)
            {

                fullURL += "?";
                foreach (KeyValuePair<string, string> entry in parameters)
                {
                    Debug.Log("get():  getting URL parameter :" + entry.Key + "=" + entry.Value);
                    fullURL += entry.Key + "=" + entry.Value + "&";
                }
                fullURL = fullURL.Substring(0, fullURL.Length - 1);
            }

            using (UnityWebRequest httpClient = UnityWebRequest.Get(fullURL)) { 

                httpClient.SetRequestHeader("x-accept-version", BITPAY_API_VERSION);
                httpClient.SetRequestHeader("x-bitpay-plugin-info", BITPAY_PLUGIN_INFO);
//                httpClient.SetRequestHeader("Content-Type", "application/json");
                    //                    String signature = KeyUtils.sign(_ecKey, fullURL);

                //string signature = _ecKey.SignMessage(fullURL);
                string text = fullURL;
                byte[] singleHash = null;
                using (var hash256 = SHA256.Create())
                {
                    var bytes = Encoding.UTF8.GetBytes(text);
                    singleHash = hash256.ComputeHash(bytes);
                }
                ECDSASignature eCDSA = _ecKey.Sign(new uint256(singleHash));
                string newsig = KeyUtils.bytesToHex(eCDSA.ToDER());

                httpClient.SetRequestHeader("x-signature", newsig );
//                    httpClient.SetRequestHeader("x-signature", signature);
                //                    byte[] pubkBytes = _ecKey.PubKey;
                byte[] pubkBytes = _ecKey.PubKey.Decompress().ToBytes();
                httpClient.SetRequestHeader("x-identity", KeyUtils.bytesToHex(pubkBytes));
                Debug.Log("GET HEADER:URL+data =" + fullURL);
                Debug.Log("GET HEADER:x-signature:" + newsig);
                Debug.Log("GET HEADER:x-identity(hex pubk):" + KeyUtils.bytesToHex(pubkBytes));

                yield return httpClient.SendWebRequest();// send request
                yield return httpClient.downloadHandler.text; // return donwloadhandler
            }


       }



        //private IEnumerator postWithSignature(String uri, String json)
        //{
        //    Debug.Log(" postWithSignature() is called.");

        //    yield  return this.post(uri, json, true);
        //}

        private IEnumerator post(String uri, String json, bool signatureRequired = false)
        {
            Debug.Log(" post() is called URI:" + uri);
            Debug.Log(" post() is called signatureRequired: " + signatureRequired);
            Debug.Log(" post() is called json before: " + json);
            json = unicodeToAscii(json);
            Debug.Log(" post() is called json after : " + json);
            using (UnityWebRequest httpClient = new UnityWebRequest(_baseUrl + uri, UnityWebRequest.kHttpVerbPOST))
            {
                httpClient.SetRequestHeader("x-accept-version", BITPAY_API_VERSION);
                httpClient.SetRequestHeader("x-bitpay-plugin-info", BITPAY_PLUGIN_INFO);
                httpClient.SetRequestHeader("Content-Type", "application/json");
                if (signatureRequired)
                {
                    //String signature = KeyUtils.sign(_ecKey, _baseUrl + uri + json);
                    string text = _baseUrl + uri + json;
                    byte[] singleHash = null;
                    using (var hash256 = SHA256.Create())
                    {
                        var bytes = Encoding.UTF8.GetBytes(text);
                        singleHash = hash256.ComputeHash(bytes);
                    }
                    ECDSASignature eCDSA = _ecKey.Sign(new uint256(singleHash));
                    string newsig = KeyUtils.bytesToHex(eCDSA.ToDER());

                    httpClient.SetRequestHeader("x-signature", newsig);
                    //                    byte[] pubkBytes = _ecKey.PubKey;
                    byte[] pubkBytes = _ecKey.PubKey.Decompress().ToBytes();

                    httpClient.SetRequestHeader("x-identity", KeyUtils.bytesToHex(pubkBytes));
                    Debug.Log("POST HEADER:data:" + _baseUrl + uri + json);
                    Debug.Log("POST HEADER:x-signature:" + newsig);
                    Debug.Log("POST HEADER:x-identity(hex pubk):" + KeyUtils.bytesToHex(pubkBytes));
                }

                UploadHandlerRaw uH = new UploadHandlerRaw(System.Text.Encoding.UTF8.GetBytes(json));
                httpClient.uploadHandler = uH;
                httpClient.downloadHandler = (DownloadHandler)new DownloadHandlerBuffer();
                UnityWebRequestAsyncOperation uwr = httpClient.SendWebRequest();// send request

                while (!uwr.isDone)
                {
                 //   Debug.Log(uwr.progress);
                    yield return null;
                }

                if (httpClient.isNetworkError || httpClient.isHttpError)
                {
                    Debug.Log("post Error:" + httpClient.error);
                    Debug.Log("post Status:" + httpClient.responseCode);
                    yield return httpClient.downloadHandler.text; // return donwloadhandler.text
                }
                else
                {
                  //  Debug.Log("postWithSignature(): Ready to download");
                    yield return httpClient.downloadHandler.text; // return donwloadhandler.text
                }
            }
        }


//        private IEnumerator post(String uri, String json, bool signatureRequired = false)
//        {
//            Debug.Log(" post() is called with "+uri);
////                            var bodyContent = new StringContent(this.unicodeToAscii(json));

//            UnityWebRequest httpClient = new UnityWebRequest(_baseUrl + uri, UnityWebRequest.kHttpVerbPOST);
//            httpClient.SetRequestHeader("x-accept-version", BITPAY_API_VERSION);
//            httpClient.SetRequestHeader("x-bitpay-plugin-info", BITPAY_PLUGIN_INFO);
//            //                bodyContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
//            httpClient.SetRequestHeader("Content-Type", "application/json");
//            if (signatureRequired)
//            {
//                String signature = KeyUtils.sign(_ecKey, _baseUrl + uri + json);
//                httpClient.SetRequestHeader("x-signature", signature);
//                httpClient.SetRequestHeader("x-identity", KeyUtils.bytesToHex(_ecKey.pubKey));
//            }
//            //                var result = _httpClient.PostAsync(uri, bodyContent).Result;
//            UploadHandlerRaw uH = new UploadHandlerRaw(System.Text.Encoding.UTF8.GetBytes(json));
//            httpClient.uploadHandler = uH;

//            yield return httpClient.SendWebRequest();// send request
//            yield return httpClient.downloadHandler; // return donwloadhandler
//        }

        private String responseToJsonString(String responseString)
        {
            if (responseString == null)
            {
                throw new BitPayException("Error: HTTP response is null");
            }

            // Get the response as a dynamic object for detecting possible error(s) or data object.
            // An error(s) object raises an exception.
            // A data object has its content extracted (throw away the data wrapper object).
//            Debug.Log(" Json Response Detail:" + responseString);

//            dynamic obj = JsonConvert.DeserializeObject(responseString);

            // Check for error response.
//            if (dynamicObjectHasProperty(obj, "error"))
            if (jsonHasString(responseString, "error"))
                {
                    Debug.Log(" responseToJsonString(): error ");
                throw new BitPayException("Error: " + responseString);
            }
            //            if (dynamicObjectHasProperty(obj, "errors"))
            if (jsonHasString(responseString, "errors"))
            {
                Debug.Log(" responseToJsonString(): errors ");
                String message = "Multiple errors:";
                //foreach (var errorItem in obj.errors)
                //{
                //    message += "\n" + errorItem.error + " " + errorItem.param;
                //}
                throw new BitPayException(message + responseString);
            }
            Debug.Log(" responseToJsonString(): No Error ");

            // Check for and exclude a "data" object from the response.
//            if (dynamicObjectHasProperty(obj, "data"))
            if (jsonHasString(responseString, "data"))
                {
                    Debug.Log(" responseToJsonString(): data found in json1 :" + responseString);
                    JObject jo = JObject.Parse(responseString);
//                responseString = jo.SelectToken("data").ToString();
                responseString = jo["data"].ToString();
                Debug.Log(" responseToJsonString(): data found in json 2:" + responseString);
            }
            //            Debug.Log(" responseToJsonString(): replaceing carrage return to empty string responseString:"+ responseString);
            //string cleanStr=  responseString.Replace("\r\n", "");
            //Debug.Log(" responseToJsonString(): result:" + cleanStr);
            //cleanStr = responseString.Replace(@"\r\n", "");
            return responseString;
        }

        private static bool jsonHasString(string json, string name)
        {
            return json.Contains(name);
        }

        //private static bool dynamicObjectHasProperty(dynamic obj, string name)
        //{
        //    bool result = false;

        //    //            if (obj.GetType() == typeof(DynamicJsonObject))
        //    if (obj.GetType() == typeof(JObject))//TODO Fix the Type CHECK
        //    {
        //        var dataValue = obj["data"];
        //        var errorValue = obj[name];
        //        result = errorValue != null;
        //        //Dictionary<string, object>.KeyCollection kc = obj.GetDynamicMemberNames();
        //        //result = kc.Contains(name);
        //    }
        //    return result;
        //}

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
