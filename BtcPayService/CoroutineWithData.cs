using System.Collections;
using UnityEngine;
namespace BTCPayAPI
{
    public class CoroutineWithData
    {
        public Coroutine coroutine { get; private set; }
        public object result;
        private IEnumerator target;
        public CoroutineWithData(MonoBehaviour owner, IEnumerator target)
        {
            this.target = target;
            this.coroutine = owner.StartCoroutine(Run());
        }

        private IEnumerator Run()
        {
            while (target.MoveNext())
            {
                result = target.Current;
                //if(result != null)
                //{
                //    Debug.Log("CoroutineWithData.Run() Type:" + result.GetType().ToString());
                //}
                //else
                //{
                //   Debug.Log("CoroutineWithData.Run() Type: null");
                //}
                yield return result;

            }
        }
    }
}
