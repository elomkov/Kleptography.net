using System;
using System.Linq;
using Chaos.NaCl;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace RsaBackdoor.Backdoor
{

	public class DsaBackdoor
	{

		public void GenerateSignature()
		{
			
			var paramsGenerator = new DsaParametersGenerator(new Sha256Digest());
			var rng = new SecureRandom(new SeededGenerator(new byte[32]));
			paramsGenerator.Init(new DsaParameterGenerationParameters(2048, 256, 80, rng));
			var paramz = paramsGenerator.GenerateParameters();

			var gen = new DsaKeyPairGenerator();
			gen.Init(new DsaKeyGenerationParameters(rng, paramz));
			var pair = gen.GenerateKeyPair();

			var signer = new DsaSigner(new BackdoorKCalculator(rng));
			signer.Init(true, new ParametersWithRandom(pair.Private, rng));
			var signature = signer.GenerateSignature(new byte[32]);

		}
	}


	public class BackdoorKCalculator : IDsaKCalculator
	{
		private BigInteger _q;


		private const string MY_PRIVATE_STR = "BDB440EBF1A77CFA014A9CD753F3F6335B1BCDD8ABE30049F10C44243BF3B6C8";
		private static readonly byte[] MY_PRIVATE = StringToByteArray(MY_PRIVATE_STR);
		private SecureRandom _rng;

		public BackdoorKCalculator(SecureRandom rng)
		{
			_rng = rng;
		}

		public static byte[] StringToByteArray(string hex)
		{
			return Enumerable.Range(0, hex.Length)
							 .Where(x => x % 2 == 0)
							 .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
							 .ToArray();
		}



		public void Init(BigInteger n, SecureRandom random)
		{
			_q = n;
		}

		public void Init(BigInteger n, BigInteger d, byte[] message)
		{

		}

		public BigInteger NextK()
		{
			var priv = new byte[32];
			BigInteger bigInteger;
			do
			{
				_rng.NextBytes(priv);
				var payload = MontgomeryCurve25519.GetPublicKey(priv);
				bigInteger = new BigInteger(payload);
			}
			while (bigInteger.SignValue < 1 || bigInteger.CompareTo(_q) >= 0);
			return bigInteger;
		}

		public bool IsDeterministic { get { return false; } }
	}

}