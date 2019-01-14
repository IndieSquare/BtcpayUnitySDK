using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using BTCPayAPI;
using BitCoinSharp;
using System.Net;
using UnityEngine;

namespace BTCBayTestClient
{
    class Program
    {
        static void Main(string[] args)
        {
            String pairingCode = "uGhQ6vx";
            String host = "btcpaytest.indiesquare.net";
            BTCPayClient bitpay = new BTCPayClient(new MonoBehaviour(),pairingCode,host);

            //New Invoice Prep
            Invoice invoice = new Invoice(1.0, "USD");
            invoice.BuyerName = "Masashi";
            invoice.BuyerEmail = "m_nakane@indiesquare.me";
            invoice.FullNotifications = true;
            invoice.NotificationEmail = "m_nakane@indiesquare.me";
            invoice.PosData = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
            invoice.ItemDesc = "Test Description";

            //Create Invoice 
            bitpay.createInvoice(invoice, printInvoice);

            //Get Invoice 
            bitpay.getInvoice(invoice.Id, printInvoice);

            //Subscribe Invoice to change
            //bitpay.subscribeInvoice(invoice.Id, printInvoice);


        }

        public static void printInvoice(Invoice invoice)
        {
            Console.WriteLine("payment is not completed:" + invoice.Status);
            Console.WriteLine(invoice.Url);
            Console.WriteLine(invoice.ToString());
            
            return;
        }
    }

}
