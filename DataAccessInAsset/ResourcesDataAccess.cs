using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using UnityEngine;
namespace BTCPayAPI
{
    public class ResourcesDataAccess
    {
        //TODO remove hard coding for generic use
        private static string resourcesPath = @"Assets/Resources/";
        private static UTF8Encoding utf8Enc = new UTF8Encoding();
        public static bool FileExists(string relativeFilePath = "poskey.txt")
        {
            string extension = System.IO.Path.GetExtension(relativeFilePath);
            string relaivePath = relativeFilePath.Substring(0, relativeFilePath.Length - extension.Length);//remove extention of relative path

            TextAsset textFile = Resources.Load<TextAsset>(relaivePath);
            Debug.Log("ResourcesDataAccess.FileExists() relativeFilePath w/o extension=" + relaivePath + " "+ (textFile==null? "null":" Not null"));
            return textFile !=null;
        }

        //Supported to use only from Unity Editor 
        //Existence check by Resources.load but writing is done by Filesystem
        public static void Save(string data, string relativeFilePath= "poskey.txt")
        {
            string dataPath = resourcesPath + relativeFilePath;
            Debug.Log("ResourcesDataAccess.Save() filesystemPath:" + dataPath +" relativePath in Resources:"+relativeFilePath);

//            BinaryFormatter binaryFormatter = new BinaryFormatter();
            FileStream fileStream;
            try
            {
                if (FileExists(relativeFilePath))//update
                {
                    File.WriteAllText(dataPath, string.Empty);
                    fileStream = File.Open(dataPath, FileMode.Open);
                }
                else// new file
                {
                    fileStream = File.Create(dataPath);
                }
                byte[] bytes = utf8Enc.GetBytes(data);
                //                binaryFormatter.Serialize(fileStream, data);
                fileStream.Write(bytes,0,bytes.Length);
                fileStream.Close();

            }
            catch (Exception e)
            {
                Debug.Log("ResourcesDataAccess.Save() " + e.ToString());
            }
        }

        public static string Load(string relativeFilePath = "poskey.txt")
        {
            string extension = System.IO.Path.GetExtension(relativeFilePath);
            string relaivePath = relativeFilePath.Substring(0, relativeFilePath.Length - extension.Length);
            TextAsset textFile = Resources.Load<TextAsset>(Path.GetFileNameWithoutExtension(relativeFilePath));
            string data = null;
            if (textFile != null)
            {
                //BinaryFormatter binaryFormatter = new BinaryFormatter();
                //using (MemoryStream memoryStream = new MemoryStream(1000))
                //{
                //    string txt = textFile.text;
                //    memoryStream.Write(txt);
                //    data = (string)binaryFormatter.Deserialize(memoryStream);
                //}

                data = textFile.text;    
            }
            else
            {
                Debug.Log("ResourcesDataAccess.Load() File not found in resources : " +relativeFilePath);
            }
            return data;
        }
    }


}
