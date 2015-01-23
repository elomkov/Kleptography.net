using System;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Tests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tests;

namespace RsaBackdoor.Backdoor
{
	public class ECDSABackdoor
	{
		public void Backdoor()
		{
			var random = new SecureRandom();
			var curve = CustomNamedCurves.GetByName("secp521r1");
			var gen = new ECKeyPairGenerator("ECDSA");
			var G = curve.G;
			var N = curve.N;
			var paramz = new ECDomainParameters(curve.Curve, G, N);
			gen.Init(new ECKeyGenerationParameters(paramz, random));

			var kCalc = new RandomDsaKCalculator();
			kCalc.Init(N, random);

			var attackersKeyPair = gen.GenerateKeyPair();

			var v = ((ECPrivateKeyParameters) attackersKeyPair.Private).D;

			var V = G.Multiply(v);

			var usersKeyPair = gen.GenerateKeyPair();
			var D = ((ECPrivateKeyParameters)usersKeyPair.Private).D;


			var m1 = new BigInteger(256, random);
			var m2 = new BigInteger(256, random);

			var k1 = kCalc.NextK();
			var R1 = G.Multiply(k1).Normalize();

			//r1 & s1 - 
			var r1 = R1.AffineXCoord.ToBigInteger().Mod(N);
			var s1 = k1.ModInverse(N).Multiply(m1.Add(D.Multiply(r1)));


			//verify signature 1
			var s = s1.ModInverse(N);
			var tmp = m1.Multiply(s).Mod(N);
			var tmp1 = r1.Multiply(s).Mod(N);
			var Q = ((ECPublicKeyParameters) usersKeyPair.Public).Q;
			var res1 = ECAlgorithms.SumOfTwoMultiplies(G, tmp, Q, tmp1).Normalize();

			bool valid = res1.AffineXCoord.ToBigInteger().Mod(N).Equals(r1);


			var a = kCalc.NextK();
			var b = kCalc.NextK();
			var h = kCalc.NextK();
			var e = kCalc.NextK();

			var u = BigInteger.One;
			var j = BigInteger.One;

			var Z = G.Multiply(k1).Multiply(a)
				.Add(V.Multiply(k1).Multiply(b))
				.Add(G.Multiply(h).Multiply(j))
				.Add(V.Multiply(e).Multiply(u))
				.Normalize();

			var zX = Z.AffineXCoord.ToBigInteger().ToByteArray();

			var hash = new byte[32];
			var sha256 = new Sha256Digest();
			sha256.BlockUpdate(zX,0,zX.Length);
			sha256.DoFinal(hash,0);

			
			var k2 = new BigInteger(hash);
			var R2 = G.Multiply(k2).Normalize();
			var r2 = R2.AffineXCoord.ToBigInteger().Mod(N);

			var s2 = k2.ModInverse(N).Multiply(m2.Add(D.Multiply(r2)));

			//verify signature 2

			s = s2.ModInverse(N);
			tmp = m2.Multiply(s).Mod(N);
			tmp1 = r2.Multiply(s).Mod(N);
			var res2 = ECAlgorithms.SumOfTwoMultiplies(G, tmp, Q, tmp1).Normalize();

			valid = res2.AffineXCoord.ToBigInteger().Mod(N).Equals(r2);

			var Z1 = res1.Multiply(a).Add(res1.Multiply(v).Multiply(b));

			var Z2 = Z1.Add(G.Multiply(j).Multiply(h)).Add(V.Multiply(u).Multiply(e)).Normalize();

			sha256.Reset();

			zX = Z2.AffineXCoord.ToBigInteger().ToByteArray();

			sha256.BlockUpdate(zX,0,zX.Length);
			sha256.DoFinal(hash,0);

			var kk = new BigInteger(hash);


		}	
	}
}