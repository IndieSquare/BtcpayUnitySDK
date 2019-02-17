using BTCPayAPI;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using UnityEngine;
using Multiformats.Base;
using System.Text;
using Org.BouncyCastle.Math;
using NBitcoin;
using System.IO;
using NBitcoin.Protocol;
using NBitcoin.Crypto;
using Org.BouncyCastle.Asn1;
using NBitcoin.DataEncoders;
using System.Security.Cryptography;
using Newtonsoft.Json;
using System.Collections.Generic;
using Newtonsoft.Json.Linq;
using System.Text.RegularExpressions;

namespace BtcPayEcKeyTest
{
    
    [TestClass]
    public class BitPayTest
    {
        EcKey _ecKey;
        Key _nbKey;
        public BitPayTest()
        {
            //            string privHexStr = "00c7a830ce41ea2f0955016b74e213da3b4ecb1fe3aaf3ea51191925f337d7f8cb";
            string privHexStr = "c7a830ce41ea2f0955016b74e213da3b4ecb1fe3aaf3ea51191925f337d7f8cb";
            byte[] bytes = KeyUtils.hexToBytes(privHexStr);
            BigInteger pkey = new BigInteger(privHexStr, 16);
            _ecKey = KeyUtils.createEcKeyFromHexString(privHexStr);


            string privHexStr2 = "c7a830ce41ea2f0955016b74e213da3b4ecb1fe3aaf3ea51191925f337d7f8cb";
            byte[] bytes2 = KeyUtils.hexToBytes(privHexStr2);
            _nbKey = new Key(bytes2,-1,false);
        }


        //BitPay EcKey
        [TestMethod]
        public void testSameSINisDerived()
        {
            //pubkey check
            Assert.AreEqual(
                 "04134f2e64c201d3fefae9f2fd5041a302130193dfec53de276e04cdc343a5ee8192a72a9e06ab057287442860aad70e7238201c7da0ada05b84eae18de530b1bf",
                 BitConverter.ToString(_ecKey.PubKey).Replace("-", String.Empty).ToLower());

            string sin = KeyUtils.deriveSIN(_ecKey);
            //SIN code generated check
            Assert.AreEqual("TfJBAqpGcvhCEVhnZYacwo21d9BMkfAWpLV", sin);
        }

        //NBitcoin EcKey
        [TestMethod]
        public void testSameSINisDerived_NB()
        {

            //pubkey check
            PubKey nbPub = _nbKey.PubKey.Decompress();
            Assert.AreEqual(
                 "04134f2e64c201d3fefae9f2fd5041a302130193dfec53de276e04cdc343a5ee8192a72a9e06ab057287442860aad70e7238201c7da0ada05b84eae18de530b1bf",
                 BitConverter.ToString(nbPub.ToBytes()).Replace("-", String.Empty).ToLower());

            string sin = KeyUtils.deriveSIN(_nbKey);
            //pubkey check
            Assert.AreEqual(
                 "04134f2e64c201d3fefae9f2fd5041a302130193dfec53de276e04cdc343a5ee8192a72a9e06ab057287442860aad70e7238201c7da0ada05b84eae18de530b1bf",
                 BitConverter.ToString(_ecKey.PubKey).Replace("-", String.Empty).ToLower());
            //SIN code generated check
            Assert.AreEqual("TfJBAqpGcvhCEVhnZYacwo21d9BMkfAWpLV", sin);
        }


        [TestMethod]
        public void testSignAndVerify1()
        {
            string fullURL = "https://btcpaytest.indiesquare.net/tokens";
            //byte[] dataBytes = Encoding.UTF8.GetBytes(fullURL);
            String hash = KeyUtils.Sha256Hash(fullURL);
            var dataBytes = KeyUtils.hexToBytes(hash);

            byte[] sigBytes = _ecKey.Sign(dataBytes);
            string sigStr = KeyUtils.bytesToHex(sigBytes);

            Assert.IsTrue(_ecKey.Verify(dataBytes, sigBytes));
        }

        [TestMethod]
        public void testSignAndVerify2()
        {
            //data is sha256-ed
            string fullURL = "https://btcpaytest.indiesquare.net/tokens";
//            String hash = KeyUtils.Sha256Hash(fullURL);//Single hash
//            byte[] dataBytes = KeyUtils.hexToBytes(hash);

            var hash256 = SHA256.Create();
            byte[] data = Encoding.UTF8.GetBytes(fullURL);
            byte[] hashBytes = hash256.ComputeHash(data);//Single hash

            //signature
            string sigStr = "3045022100f1467b7c8348521740a99fe92772e953350421a472da908531af0d0177cc7fee02201391387f27f9ad380d5acae31af35863ac40f2a45aa18c73868e3619d05a2ae6";
            byte[] sigBytes = KeyUtils.hexToBytes(sigStr);

            //Bitpay verify
            Assert.IsTrue(_ecKey.Verify(hashBytes, sigBytes));

            //Nbitcoin verify
            PubKey pubk = _nbKey.PubKey.Decompress();
            Assert.IsTrue(pubk.Verify(new uint256(hashBytes), new ECDSASignature(Encoders.Hex.DecodeData(sigStr))));

        }

        [TestMethod]
        public void testSignAndVerify1_NB()
        {
            //Single hash
            string fullURL = "https://btcpaytest.indiesquare.net/tokens";
            byte[] data = Encoding.UTF8.GetBytes(fullURL);
            byte[] singleHash=null;
            using (var hash256 = SHA256.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(fullURL);
                singleHash = hash256.ComputeHash(bytes);
            }

            //string sig = _nbKey.SignMessage(fullURL);//Double hashed and base64 but NOT DER 
            //byte[] doubleHashedSig = Convert.FromBase64String(sig);

            ECDSASignature eCDSA = _nbKey.Sign(new uint256(singleHash));
            string sigDERStr = KeyUtils.bytesToHex(eCDSA.ToDER());

            // bitpay verify
            Assert.IsTrue(_ecKey.Verify(singleHash, eCDSA.ToDER()));

            //NBitcoin verify
            PubKey pubk = _nbKey.PubKey;
            Assert.IsTrue(pubk.Verify(new uint256(singleHash), new ECDSASignature(eCDSA.ToDER())));
            //Assert.IsTrue(pubk.Verify(doubleHash, new ECDSASignature(doubleHashedSig)));//NOT DER
        }

        [TestMethod]
        public void testSignAndVerify2_NB()
        {
            //Double Hash
            string fullURL = "https://btcpaytest.indiesquare.net/tokens";
            byte[] data = Encoding.UTF8.GetBytes(fullURL);
            uint256 doubleHash = Hashes.Hash256(data);

            //Sign
            ECDSASignature eCDSA = _nbKey.Sign(doubleHash);
            string sigDERStr = KeyUtils.bytesToHex(eCDSA.ToDER());

            // bitpay verify
            Assert.IsTrue(_ecKey.Verify(doubleHash.ToBytes(), Encoders.Hex.DecodeData(sigDERStr)));

            //NBitcoin verify
            PubKey pubk = _nbKey.PubKey;
            Assert.IsTrue(pubk.Verify(doubleHash, new ECDSASignature(Encoders.Hex.DecodeData(sigDERStr))));
            //Assert.IsTrue(pubk.Verify(doubleHash, new ECDSASignature(doubleHashedSig)));//NOT DER
        }




        [TestMethod]
        public void testPrivateKeySave()
        {
            KeyUtils.saveEcKey(_nbKey);

            //using (FileStream fs = File.OpenRead(PRIV_KEY_FILENAME))
            //{
            //    byte[] b = new byte[1024];
            //    fs.Read(b, 0, b.Length);
            //    string base58 = new Base58Encoding().Encode(b);
            //    Debug.Log("loadEcKey():Base58 of prvkey:" + base58);
            //    EcKey key = EcKey.FromAsn1(b);

            }

        [TestMethod]
        public void testPrivateKeyLoad()
        {

            //FileStream fs = new FileStream(PRIV_KEY_FILENAME, FileMode.Create, FileAccess.Write);
            //fs.Write(bytes, 0, bytes.Length);
            //fs.Close();

            Key nbKey = KeyUtils.loadNBEcKey();

        }

        [TestMethod]
        public void testTokenJsonDeserialize()
        {
            string json = @"{'data':[{'pos':'G4AcnWpGtMDw2p1Ci1h1ommxUs4GJdzurbKFdLqCyLEv'},{'merchant':'G4AcnWpGtMDw2p1Ci1h1ommxUs4GJdzurbKFdLqCyLEv'}]}";
            //string json = @"[{'pos':'G4AcnWpGtMDw2p1Ci1h1ommxUs4GJdzurbKFdLqCyLEv'},{'merchant':'G4AcnWpGtMDw2p1Ci1h1ommxUs4GJdzurbKFdLqCyLEv'}]";
            json = JObject.Parse(json).SelectToken("data").ToString();
            json = json.Replace(@"\r\n", "");
            List<Dictionary<string, string>> map = JsonConvert.DeserializeObject<List<Dictionary<string, string>>>(json);
            //SIN code generated check
            Assert.AreEqual(map.Count, 2);
            string val;
            map[0].TryGetValue("pos", out val);
            Assert.AreEqual(val, "G4AcnWpGtMDw2p1Ci1h1ommxUs4GJdzurbKFdLqCyLEv");
            map[1].TryGetValue("merchant", out val);
            Assert.AreEqual(val, "G4AcnWpGtMDw2p1Ci1h1ommxUs4GJdzurbKFdLqCyLEv");
        }
    }
}
