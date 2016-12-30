using System;
using LibP2P.Crypto;
using Multiformats.Base;
using Multiformats.Hash;
using Multiformats.Hash.Algorithms;
using NUnit.Framework;

namespace LibP2P.Peer.Tests
{
    [TestFixture]
    public class PeerIdTests
    {
        private class KeySet
        {
            public PrivateKey sk { get; protected set; }
            public PublicKey pk { get; protected set; }
            public string hpk { get; protected set; }
            public string hpkp { get; protected set; }

            protected KeySet() { }

            public static KeySet Generate()
            {
                var pair = KeyPair.Generate(KeyType.RSA, 512);

                var h = Multihash.Sum<SHA2_256>(pair.PublicKey.Bytes);
                var ks = new KeySet
                {
                    sk = pair.PrivateKey,
                    pk = pair.PublicKey,
                    hpk = h.ToString(Multibase.Base16),
                    hpkp = h.ToString(Multibase.Base58)
                };
                return ks;
            }

            public static KeySet Load(string hpkp, string skBytesStr)
            {
                var skBytes = Convert.FromBase64String(skBytesStr);
                var ks = new KeySet {sk = PrivateKey.Unmarshal(skBytes)};
                ks.pk = ks.sk.GetPublic();
                var h = Multihash.Sum<SHA2_256>(ks.pk.Bytes);
                ks.hpk = h.ToString(Multibase.Base16);
                ks.hpkp = h.ToString(Multibase.Base58);
                if (ks.hpkp != hpkp)
                    throw new Exception($"hpkp doesn't match key. want: {hpkp}, got: {ks.hpkp}");

                return ks;
            }
        }

        private KeySet gen1;
        private KeySet gen2;
        private KeySet man;
        private const string hpkpMan = "QmRK3JgmVEGiewxWbhpXLJyjWuGuLeSTMTndA1coMHEy5o";
        private const string skManBytes = "CAAS4AQwggJcAgEAAoGBAL7w+Wc4VhZhCdM/+Hccg5Nrf4q9NXWwJylbSrXz/unFS24wyk6pEk0zi3W7li+vSNVO+NtJQw9qGNAMtQKjVTP+3Vt/jfQRnQM3s6awojtjueEWuLYVt62z7mofOhCtj+VwIdZNBo/EkLZ0ETfcvN5LVtLYa8JkXybnOPsLvK+PAgMBAAECgYBdk09HDM7zzL657uHfzfOVrdslrTCj6p5moDzvCxLkkjIzYGnlPuqfNyGjozkpSWgSUc+X+EGLLl3WqEOVdWJtbM61fewEHlRTM5JzScvwrJ39t7o6CCAjKA0cBWBd6UWgbN/t53RoWvh9HrA2AW5YrT0ZiAgKe9y7EMUaENVJ8QJBAPhpdmb4ZL4Fkm4OKiaNEcjzn6mGTlZtef7K/0oRC9+2JkQnCuf6HBpaRhJoCJYg7DW8ZY+AV6xClKrgjBOfERMCQQDExhnzu2dsQ9k8QChBlpHO0TRbZBiQfC70oU31kM1AeLseZRmrxv9Yxzdl8D693NNWS2JbKOXl0kMHHcuGQLMVAkBZ7WvkmPV3aPL6jnwp2pXepntdVnaTiSxJ1dkXShZ/VSSDNZMYKY306EtHrIu3NZHtXhdyHKcggDXrqkBrdgErAkAlpGPojUwemOggr4FD8sLX1ot2hDJyyV7OK2FXfajWEYJyMRL1Gm9Uk1+Un53RAkJneqpJGAzKpyttXBTIDO51AkEA98KTiROMnnU8Y6Mgcvr68/SMIsvCYMt9/mtwSBGgl80VaTQ5Hpaktl6XbhVUt5Wv0tRxlXZiViCGCD1EtrrwTw==";

        [SetUp]
        public void Setup()
        {
            gen1 = KeySet.Generate();
            gen2 = KeySet.Generate();
            man = KeySet.Load(hpkpMan, skManBytes);
        }

        [Test]
        public void TestIdMatchesPublicKey()
        {
            Action<KeySet> test = (ks) =>
            {
                var p1 = PeerId.Decode(ks.hpkp);
                Assert.That(p1.ToString(Multibase.Base16), Is.EqualTo(ks.hpk));
                Assert.That(p1.MatchesPublicKey(ks.pk), Is.True);

                var p2 = new PeerId(ks.pk);
                Assert.That(p1, Is.EqualTo(p2));
                Assert.That(p2.ToString(Multibase.Base58), Is.EqualTo(ks.hpkp));
            };

            test(gen1);
            test(gen2);
            test(man);
        }

        [Test]
        public void TestIdMatchesPrivateKey()
        {
            Action<KeySet> test = (ks) =>
            {
                var p1 = PeerId.Decode(ks.hpkp);
                Assert.That(p1.ToString(Multibase.Base16), Is.EqualTo(ks.hpk));
                Assert.That(p1.MatchesPrivateKey(ks.sk), Is.True);

                var p2 = new PeerId(ks.sk);
                Assert.That(p1, Is.EqualTo(p2));
            };

            test(gen1);
            test(gen2);
            test(man);
        }
    }
}
