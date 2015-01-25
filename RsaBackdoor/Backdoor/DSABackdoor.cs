using System;
using System.Linq;
<<<<<<< origin/DSABackdoor
=======
using System.Runtime.InteropServices;
using System.Text;
>>>>>>> local
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
<<<<<<< origin/DSABackdoor
			
			var paramsGenerator = new DsaParametersGenerator(new Sha256Digest());
			var rng = new SecureRandom(new SeededGenerator(new byte[32]));
			paramsGenerator.Init(new DsaParameterGenerationParameters(2048, 256, 80, rng));
=======
            var random = new SecureRandom();
			var paramsGenerator = new DsaParametersGenerator(new Sha256Digest());
			var rng = new SecureRandom(new SeededGenerator(new byte[32]));
			paramsGenerator.Init(new DsaParameterGenerationParameters(1024, 160, 80, rng));
>>>>>>> local
			var paramz = paramsGenerator.GenerateParameters();

			var gen = new DsaKeyPairGenerator();
			gen.Init(new DsaKeyGenerationParameters(rng, paramz));
			var pair = gen.GenerateKeyPair();

<<<<<<< origin/DSABackdoor
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

=======
		    var p = paramz.P;
		    var q = paramz.Q;
		    var g = paramz.G;

		    var x = ((DsaPrivateKeyParameters) pair.Private).X;
		    var y = ((DsaPublicKeyParameters) pair.Public).Y;

            var attackersPair  = gen.GenerateKeyPair();

            var v = ((DsaPrivateKeyParameters)attackersPair.Private).X;
            var V = ((DsaPublicKeyParameters)attackersPair.Public).Y;
            
            var kCalc = new RandomDsaKCalculator(); // kCalc generates random values [1, N-1]
            kCalc.Init(q, random);

		    var k1 = kCalc.NextK();

            const string message1 = "First message to sign";
            var m1 = new BigInteger(1, Hash(Encoding.UTF8.GetBytes(message1))); // hash of m1

		    var r1 = g.ModPow(k1, p).Mod(q);
		    var s1 = k1.ModInverse(q).Multiply(m1.Add(x.Multiply(r1))).Mod(q);

            //verify

            var w = s1.ModInverse(q).Mod(q);
		    var u1 = m1.Multiply(w).Mod(q);
		    var u2 = r1.Multiply(w).Mod(q);
		    var v1 = g.ModPow(u1, p).Multiply(y.ModPow(u2, p)).Mod(p).Mod(q);

		    var valid1 = v1.Equals(r1);

            const string message2 = "Second message to sign";
            var m2 = new BigInteger(1, Hash(Encoding.UTF8.GetBytes(message2))); // hash of m2

            //here we generate a,b,h,e < N using seed = hash(m2)
            kCalc.Init(q, new SecureRandom(new SeededGenerator(Hash(Encoding.UTF8.GetBytes(message2)))));

            var a = kCalc.NextK();
            var b = kCalc.NextK();
            var h = kCalc.NextK();
            var e = kCalc.NextK();
            
            //u,j - true random
            var u = BigInteger.One;//(random.Next() % 2) == 1 ? BigInteger.One : BigInteger.Zero;
            var j = BigInteger.One;//(random.Next() % 2) == 1 ? BigInteger.One : BigInteger.Zero;


            //compute hidden field element
            var Z = g.ModPow(k1,p).ModPow(a,p)
                .Multiply(V.ModPow(k1,p).ModPow(b,p))
                .Multiply(g.ModPow(h,p).ModPow(j,p))
                .Multiply(V.ModPow(e,p).ModPow(u,p))
                .Mod(q);

		    var k2 = Z;

            var r2 = g.ModPow(k2, p).Mod(q);
            var s2 = k2.ModInverse(q).Multiply(m2.Add(x.Multiply(r2))).Mod(q);

            //verify

            w = s2.ModInverse(q).Mod(q);
            u1 = m2.Multiply(w).Mod(q);
            u2 = r2.Multiply(w).Mod(q);
            var v2 = g.ModPow(u1, p).Multiply(y.ModPow(u2, p)).Mod(p).Mod(q);

            var valid2 = v2.Equals(r2);

            var Z1 = v1.ModPow(a,p).Multiply(v1.ModPow(v,p).ModPow(b,p)).Mod(q);

		    var Z2 = Z1.Multiply(g.ModPow(j,p).ModPow(h,p)).Multiply(V.ModPow(u,p).ModPow(e,p)).Mod(q);



		}

        private byte[] Hash(byte[] data)
        {
            var hash = new byte[32];
            var sha256 = new Sha256Digest();
            sha256.BlockUpdate(data, 0, data.Length);
            sha256.DoFinal(hash, 0);
            return hash;
        }
	}


	

>>>>>>> local
}