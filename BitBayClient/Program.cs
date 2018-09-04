using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using BitPayAPI;
using BitCoinSharp;
using System.Net;
using WebSocketSharp;

namespace BitBayClient
{
    class Program
    {
        static void Main(string[] args)
        {
            //Priv Encoded:92u161MFAiv7HvisGfxppaxpD3bx34u7Xm15tR1s4vop9fgxT42
            //Priv bytes HEX:ACC29371ED11660DF4843F1D0EE9316B095BF4D2912AA54D4543F238208614C0
            //Pub bytes HEX:041E52AD0A7B26181A364A1CDBBDBE90C93485B909FAD17D0F1F4E05C693AB512DE9B0D56A98C126CDB38AAE9BBB3EC1774C8111F4DBAFCA09E66DDBAB53327BB1

            //Label Unity Test
            //Facade  merchant
            //SIN Tf8z2zcpoJdgijLF35aVLgh8a6CXv8RDm92

            //EcKey key = KeyUtils.createEcKey();
            //Console.WriteLine("Priv Encoded:"+key.GetPrivateKeyEncoded(NetworkParameters.TestNet()));
            //Console.WriteLine("Priv bytes HEX:"+BitConverter.ToString(key.GetPrivKeyBytes()).Replace("-", ""));
            //Console.WriteLine("Pub bytes HEX:"+ BitConverter.ToString(key.PubKey).Replace("-", ""));
            //Console.WriteLine("STOP");

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            String pairingCode = "m9mxX5Z";
            String clientName = "unity client 3";
            BitPay bitpay = new BitPay(clientName);

            // Is this client already authorized to use the POS facade?
            if (!bitpay.clientIsAuthorized(BitPay.FACADE_MERCHANT))
            {
                // Get POS facade authorization.
                bitpay.authorizeClient(pairingCode);
            }


            Invoice invoice = new Invoice(1.0, "USD");
            invoice.BuyerName = "Masashi";
            invoice.BuyerEmail = "masashi.nakane@google.com";
            invoice.FullNotifications = true;
            invoice.NotificationEmail = "m_nakane@indiesquare.me";
            invoice.PosData = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
            invoice.BtcPrice = 0;
            invoice.ItemDesc = "TEst DEc";

            invoice = bitpay.createInvoice(invoice, "merchant");
            Console.WriteLine("Invoice:" + invoice.ToString());

            Invoice inv = bitpay.getInvoice(invoice.Id, BitPay.FACADE_MERCHANT);

            //WebSocket  loop
            using (var ws = new WebSocket("wss://btcpaytest.indiesquare.net/i/" + invoice.Id + "/status/ws"))
            {
                ws.OnMessage += (sender, e) =>
                  Console.WriteLine("Laputa says: " + e.Data);

                ws.Connect();
                ws.Send("BALUS");
                Console.ReadKey(true);
            }


            Console.WriteLine("STOP");
        }
    }
}
