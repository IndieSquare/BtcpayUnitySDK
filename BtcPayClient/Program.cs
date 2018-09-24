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
            String pairingCode = "vT5iJ1b";
            BTCPayClient bitpay = new BTCPayClient(pairingCode);

            //New Invoice Prep
            Invoice invoice = new Invoice(1.0, "USD");
            invoice.BuyerName = "Masashi";
            invoice.BuyerEmail = "m_nakane@indiesquare.me";
            invoice.FullNotifications = true;
            invoice.NotificationEmail = "m_nakane@indiesquare.me";
            invoice.PosData = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
            invoice.ItemDesc = "Test Description";

            //Create Invoice 
            invoice = bitpay.createInvoice(invoice, "merchant");
            Console.WriteLine("Invoice Created:" + invoice.Id);
            Console.WriteLine("Invoice Url:" + invoice.Url);

            //Get Invoice 
            Invoice inv = bitpay.getInvoice(invoice.Id, BTCPayClient.FACADE_MERCHANT);

            //Subscribe Invoice to change
            Task<Invoice> t = bitpay.GetInvoiceAsync(invoice.Id);
            Console.WriteLine(t.Status);
            t.Wait();
            Invoice invo = t.Result;

            Console.WriteLine(invo.Url);
            Console.WriteLine(invo.ToString());

        }
    }
}
