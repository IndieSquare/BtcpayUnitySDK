using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Serialization.Formatters.Binary;
using UnityEngine;

/**
* 
*  This class deals with storing data in user level.
*  It stores file in User's folder specified by Unity spec.
*  https://docs.unity3d.com/ScriptReference/Application-persistentDataPath.html
*  This class handles both non-webGL and webGL.
*/
public class DataAccess
{
    [DllImport("__Internal")]
    private static extern void SyncFiles();

    [DllImport("__Internal")]
    private static extern void WindowAlert(string message);

    private static string filePath = "{0}/poskey.dat";

    public static bool FileExists()
    {
        string dataPath = string.Format(filePath, Application.persistentDataPath);
        Debug.Log("FileExists():checking the file:"+dataPath);
        return File.Exists(dataPath);
    }

    public static void Save(string gameDetails)
    {
        string dataPath = string.Format(filePath, Application.persistentDataPath);
        BinaryFormatter binaryFormatter = new BinaryFormatter();
        FileStream fileStream;

        try
        {
            if (File.Exists(dataPath))
            {
                File.WriteAllText(dataPath, string.Empty);
                fileStream = File.Open(dataPath, FileMode.Open);
            }
            else
            {
                fileStream = File.Create(dataPath);
            }

            binaryFormatter.Serialize(fileStream, gameDetails);
            fileStream.Close();

            if (Application.platform == RuntimePlatform.WebGLPlayer)
            {
                SyncFiles();
            }
        }
        catch (Exception e)
        {
            PlatformSafeMessage("Failed to Save: " + e.Message);
        }
    }

    public static string Load()
    {
        string gameDetails = null;
        string dataPath = string.Format(filePath, Application.persistentDataPath);

        try
        {
            if (File.Exists(dataPath))
            {
                BinaryFormatter binaryFormatter = new BinaryFormatter();
                FileStream fileStream = File.Open(dataPath, FileMode.Open);

                gameDetails = (string)binaryFormatter.Deserialize(fileStream);
                fileStream.Close();
            }
        }
        catch (Exception e)
        {
            PlatformSafeMessage("Failed to Load: " + e.Message);
        }

        return gameDetails;
    }

    private static void PlatformSafeMessage(string message)
    {
        if (Application.platform == RuntimePlatform.WebGLPlayer)
        {
            WindowAlert(message);
        }
        else
        {
            Debug.Log(message);
        }
    }
}