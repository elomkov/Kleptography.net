using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Chaos.NaCl;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using RsaBackdoor.Backdoor;

namespace RsaBackdoor
{
	class Program
	{
		static void Main(string[] args)
		{

			new DsaBackdoor().GenerateSignature();

			var backdoorEngine = new RsaBackdoorEngine();
			var randomKeyPair = backdoorEngine.BuildRandomKey();

			var payload = backdoorEngine.ExtractPayload((RsaKeyParameters) randomKeyPair.Public);

			var restoredKey = backdoorEngine.BuildKeyFromPayload(payload);

			var initialParams = ((RsaPrivateCrtKeyParameters)randomKeyPair.Private);
			var restoredParams = ((RsaPrivateCrtKeyParameters)restoredKey.Private);
			Console.WriteLine(initialParams.P.Equals(restoredParams.P) && initialParams.Q.Equals(restoredParams.Q));
			Console.ReadKey();
		}
	}
}
