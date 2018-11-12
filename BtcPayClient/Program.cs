using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using BTCPayAPI;
using BitCoinSharp;
using System.Net;


namespace BTCBayTestClient
{
    class Program
    {
        static void Main(string[] args)
        {
            String pairingCode = "uGhQ6vx";
            String host = "btcpaytest.indiesquare.net";
            BTCPayClient bitpay = new BTCPayClient(pairingCode,host);

            //New Invoice Prep
            Invoice invoice = new Invoice(1.0, "USD");
            invoice.BuyerName = "Masashi";
            invoice.BuyerEmail = "m_nakane@indiesquare.me";
            invoice.FullNotifications = true;
            invoice.NotificationEmail = "m_nakane@indiesquare.me";
            invoice.PosData = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
            invoice.ItemDesc = "Test Description";

            //Create Invoice 
            invoice = bitpay.createInvoice(invoice);
            Console.WriteLine("Invoice Created:" + invoice.Id);
            Console.WriteLine("Invoice Url:" + invoice.Url);

            //Get Invoice 
            Invoice inv = bitpay.getInvoice(invoice.Id);

            //Subscribe Invoice to change
            Task t = bitpay.subscribeInvoiceAsync(invoice.Id, printInvoice);
            t.Wait();
            Console.WriteLine(t.Status);

            Console.WriteLine(t.Status);

        }

        public static async Task printInvoice(Invoice invoice)
        {
            Console.WriteLine("payment is not completed:" + invoice.Status);
            Console.WriteLine(invoice.Url);
            Console.WriteLine(invoice.ToString());
            await Task.Delay(1000);
            return;
        }
    }
}
