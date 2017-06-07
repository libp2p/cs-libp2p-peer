using System;
using System.Linq;
using System.Text;
using LibP2P.Crypto;
using Multiformats.Base;
using Multiformats.Hash;
using Multiformats.Hash.Algorithms;

namespace LibP2P.Peer
{
    public class PeerId : IComparable<PeerId>, IEquatable<PeerId>
    {
        private readonly byte[] _value;

        public PeerId(byte[] bytes)
        {
            _value = bytes;
        }

        public PeerId(string s)
            : this(Encoding.UTF8.GetBytes(s))
        {
        }

        public PeerId(Multihash mh)
            : this((byte[])mh)
        {
        }

        public PeerId(PublicKey pk)
            : this(Multihash.Sum<SHA2_256>(pk.Bytes))
        {
        }

        public PeerId(PrivateKey sk)
            : this(sk.GetPublic())
        {
        }

        public int CompareTo(PeerId other) => string.Compare(ToString(Multibase.Base16), other.ToString(Multibase.Base16), StringComparison.Ordinal);

        public bool Equals(PeerId other) => _value.SequenceEqual(other?._value ?? Array.Empty<byte>());

        public override bool Equals(object obj)
        {
            var other = (PeerId) obj;
            return other != null && Equals(other);
        }

        public override int GetHashCode() => _value.GetHashCode();

        public override string ToString()
        {
            var id = ToString(Multibase.Base58);
            if (id.StartsWith("Qm"))
                id = id.Substring(2);

            var max = Math.Max(6, id.Length);
            return $"<PeerId {id.Substring(0, max)}>";
        }

        public string ToString(MultibaseEncoding encoding) => Multibase.EncodeRaw(encoding, _value);

        public bool MatchesPrivateKey(PrivateKey sk) => MatchesPublicKey(sk.GetPublic());
        public bool MatchesPublicKey(PublicKey pk) => new PeerId(pk).Equals(this);

        public static PeerId Decode(string s)
        {
            Multihash mh;
            return Multihash.TryParse(s, out mh) ? new PeerId(mh) : new PeerId(Multibase.DecodeRaw<Base16Encoding>(s.ToUpper()));
        }

        public static implicit operator PeerId(string value) => new PeerId(value);
        public static implicit operator string(PeerId id) => Encoding.UTF8.GetString(id._value);
        public static implicit operator PeerId(byte[] bytes) => new PeerId(bytes);
        public static implicit operator byte[](PeerId id) => id._value;
    }
}
