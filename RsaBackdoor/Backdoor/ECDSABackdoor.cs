using System;
using System.Text;
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

			var kCalc = new RandomDsaKCalculator(); // kCalc generates random values [1, N-1]
			kCalc.Init(N, random);

			var attackersKeyPair = gen.GenerateKeyPair();

			var v = ((ECPrivateKeyParameters) attackersKeyPair.Private).D; //attacker's private
            var V = G.Multiply(v); //attackers public

			var usersKeyPair = gen.GenerateKeyPair(); //user's public
			var D = ((ECPrivateKeyParameters)usersKeyPair.Private).D; //user's private


		    var message1 = "First message to sign";
            var message2 = "Second message to sign";



			var m1 = new BigInteger(1, Hash(Encoding.UTF8.GetBytes(message1))); // hash of m1
            var m2 = new BigInteger(1, Hash(Encoding.UTF8.GetBytes(message2))); // hash of m2

			var k1 = kCalc.NextK(); // k1 is random
			var R1 = G.Multiply(k1).Normalize();

			//(r1, s1) - signature 1
			var r1 = R1.AffineXCoord.ToBigInteger().Mod(N);
			var s1 = k1.ModInverse(N).Multiply(m1.Add(D.Multiply(r1)));


			//verify signature 1
			var s = s1.ModInverse(N);
			var tmp = m1.Multiply(s).Mod(N);
			var tmp1 = r1.Multiply(s).Mod(N);
			var Q = ((ECPublicKeyParameters) usersKeyPair.Public).Q;
			var res1 = ECAlgorithms.SumOfTwoMultiplies(G, tmp, Q, tmp1).Normalize();

			bool valid1 = res1.AffineXCoord.ToBigInteger().Mod(N).Equals(r1);


            //Generate signature 2


            //here we generate a,b,h,e < N using seed = hash(m2)
            kCalc.Init(N, new SecureRandom(new SeededGenerator(Hash(Encoding.UTF8.GetBytes(message2)))));

			var a = kCalc.NextK();
			var b = kCalc.NextK();
			var h = kCalc.NextK();
			var e = kCalc.NextK();

            //u,j - true random
			var u = (random.Next() % 2) == 1 ? BigInteger.One : BigInteger.Zero;
            var j = (random.Next() % 2) == 1 ? BigInteger.One : BigInteger.Zero;

            //compute hidden field element
			var Z = G.Multiply(k1).Multiply(a)
				.Add(V.Multiply(k1).Multiply(b))
				.Add(G.Multiply(h).Multiply(j))
				.Add(V.Multiply(e).Multiply(u))
				.Normalize();

			var zX = Z.AffineXCoord.ToBigInteger().ToByteArray();

		    var hash = Hash(zX);
            var k2 = new BigInteger(1,hash);
			var R2 = G.Multiply(k2).Normalize();

            //(r2, s2) = signature 2
			var r2 = R2.AffineXCoord.ToBigInteger().Mod(N);
            var s2 = k2.ModInverse(N).Multiply(m2.Add(D.Multiply(r2)));

			//verify signature 2

			s = s2.ModInverse(N);
			tmp = m2.Multiply(s).Mod(N);
			tmp1 = r2.Multiply(s).Mod(N);
			var res2 = ECAlgorithms.SumOfTwoMultiplies(G, tmp, Q, tmp1).Normalize();

			var valid2 = res2.AffineXCoord.ToBigInteger().Mod(N).Equals(r2);

		    if (valid1 && valid2)
            {
                //compute user's private key
                var d = GetUsersPrivateKey(G, N, message2, m1, m2, r1, s1, r2, s2, v, V, Q);
                Console.WriteLine("Ecdsa private key restored: {0}",d.Equals(D));    
		    }
		    else
		    {
                Console.WriteLine("Something's wrong");    
		    }
		}

	    private byte[] Hash(byte[] data)
	    {
            var hash = new byte[32];
            var sha256 = new Sha256Digest();
            sha256.BlockUpdate(data, 0, data.Length);
            sha256.DoFinal(hash, 0);
	        return hash;
	    }

	    private BigInteger GetUsersPrivateKey(
            ECPoint G, BigInteger N,
            string message2,
            BigInteger m1, BigInteger m2,
            BigInteger r1, BigInteger s1,
            BigInteger r2, BigInteger s2,
            BigInteger v, ECPoint V,
            ECPoint Q)
	    {
            //calculate the result of verifying signature 1
            var s = s1.ModInverse(N);
            var tmp = m1.Multiply(s).Mod(N);
            var tmp1 = r1.Multiply(s).Mod(N);
            var res1 = ECAlgorithms.SumOfTwoMultiplies(G, tmp, Q, tmp1).Normalize();

            //reinit K calculator to reproduce a,b,h,e
	        var kCalc = new RandomDsaKCalculator();
            kCalc.Init(N, new SecureRandom(new SeededGenerator(Hash(Encoding.UTF8.GetBytes(message2)))));

            var a = kCalc.NextK();
            var b = kCalc.NextK();
            var h = kCalc.NextK();
            var e = kCalc.NextK();

            var Z1 = res1.Multiply(a).Add(res1.Multiply(v).Multiply(b));

            //cycle through all possible j & u
            for(int i = 0; i<2; i++)
                for (int l = 0; l < 2; l++)
                {
                    var j = new BigInteger(i.ToString());
                    var u = new BigInteger(l.ToString());


                    var Z2 = Z1.Add(G.Multiply(j).Multiply(h)).Add(V.Multiply(u).Multiply(e)).Normalize();
                    var zX = Z2.AffineXCoord.ToBigInteger().ToByteArray();
                    var hash = Hash(zX);
                    var kk = new BigInteger(1, hash);
                    var R2 = G.Multiply(kk).Normalize();
                    var rr = R2.AffineXCoord.ToBigInteger().Mod(N);

                    if (rr.Equals(r2)) // Gotcha!
                    {
                       return  s2.Multiply(kk).Subtract(m2).Multiply(r2.ModInverse(N)).Mod(N);
                    }
                }

	        return null;
	    }
	}
}