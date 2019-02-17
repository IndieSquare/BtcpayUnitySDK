using System;
using System.Collections.Generic;
using System.Text;
using System.Collections;
using UnityEngine;

public class WebSocket
{
    private Uri mUrl;

    public WebSocket(Uri url)
    {
        mUrl = url;

        Debug.Log("WebSocket Constructor non-WebGL: url: " + url.AbsolutePath);

        string protocol = mUrl.Scheme;
        if (!protocol.Equals("ws") && !protocol.Equals("wss"))
            throw new ArgumentException("Unsupported protocol: " + protocol);
    }

    public void SendString(string str)
    {
        Send(Encoding.UTF8.GetBytes(str));
    }

    public string RecvString()
    {
        byte[] retval = Recv();
        Debug.Log("WebSocket.RecvString() non-WebGL: received byte size 2" + (retval == null ? "null" : retval.Length+"" ));
        if (retval == null)
            return null;
        return Encoding.UTF8.GetString(retval);
    }


    WebSocketSharp.WebSocket m_Socket;
    Queue<byte[]> m_Messages = new Queue<byte[]>();
    bool m_IsConnected = false;
    string m_Error = null;

    public IEnumerator Connect()
    {
        Debug.Log("WebSocket.Connect() non-WebGL: IN");
        m_Socket = new WebSocketSharp.WebSocket(mUrl.ToString());
        m_Socket.OnMessage += (sender, e) => m_Messages.Enqueue(e.RawData);
        m_Socket.OnOpen += (sender, e) => m_IsConnected = true;
        m_Socket.OnError += (sender, e) => m_Error = e.Message;
        m_Socket.ConnectAsync();
        Debug.Log("WebSocket.Connect() non-WebGL: after  ConnectAsync()");

        while (!m_IsConnected && m_Error == null)
        {
            Debug.Log("WebSocket.Connect() non-WebGL: Connecting:");
            yield return 0;
        }

        Debug.Log("WebSocket.Connect() non-WebGL: Connected:" + m_IsConnected +" Error:" + m_Error + " m_Messages.size():"+ m_Messages.Count);
    }

    public void Send(byte[] buffer)
    {
        m_Socket.Send(buffer);
    }

    public byte[] Recv()
    {
        if (m_Messages.Count == 0)
        {
            Debug.Log("WebSocket.Recv() non-WebGL: m_Messages.Count 1:"+ m_Messages.Count);
            return null;
        }
        Debug.Log("WebSocket.Recv() non-WebGL: m_Messages.Count 2:" + m_Messages.Count);
        return m_Messages.Dequeue();
    }

    public void Close()
    {
        m_Socket.Close();
    }

    public string error
    {
        get
        {
            return m_Error;
        }
    }
}