using System.Formats.Asn1;

namespace BoltShell.Core.Rdp;

/// <summary>
/// RDCleanPath PDU (IronRDP / Devolutions Gateway), DER encoded with EXPLICIT context tags:
/// <code>
/// RDCleanPathPdu ::= SEQUENCE {
///   version            [0] INTEGER,          -- 3390
///   error              [1] RDCleanPathErr OPTIONAL,
///   destination        [2] UTF8String OPTIONAL,
///   proxyAuth          [3] UTF8String OPTIONAL,
///   serverAuth         [4] UTF8String OPTIONAL,
///   preconnectionBlob  [5] UTF8String OPTIONAL,
///   x224ConnectionPdu  [6] OCTET STRING OPTIONAL,
///   serverCertChain    [7] SEQUENCE OF OCTET STRING OPTIONAL,
///   serverAddr         [9] UTF8String OPTIONAL }
/// RDCleanPathErr ::= SEQUENCE { errorCode [0] INTEGER, httpStatusCode [1] INTEGER OPTIONAL,
///                               wsaLastError [2] INTEGER OPTIONAL, tlsAlertCode [3] INTEGER OPTIONAL }
/// </code>
/// </summary>
public sealed record RdCleanPathPdu
{
    public const long Version1 = 3390;
    public const int GeneralError = 1;
    public const int NegotiationError = 2;

    public long Version { get; init; } = Version1;
    public RdCleanPathError? Error { get; init; }
    public string? Destination { get; init; }
    public string? ProxyAuth { get; init; }
    public string? ServerAuth { get; init; }
    public string? PreconnectionBlob { get; init; }
    public byte[]? X224ConnectionPdu { get; init; }
    public IReadOnlyList<byte[]>? ServerCertChain { get; init; }
    public string? ServerAddr { get; init; }

    /// <summary>Total length of the DER value at the start of <paramref name="buffer"/>, or null if more bytes are needed.</summary>
    public static int? CompleteLength(ReadOnlySpan<byte> buffer) =>
        AsnDecoder.TryReadEncodedValue(buffer, AsnEncodingRules.DER, out _, out _, out _, out var consumed) ? consumed : null;

    public static RdCleanPathPdu Decode(ReadOnlyMemory<byte> der)
    {
        var sequence = new AsnReader(der, AsnEncodingRules.DER).ReadSequence();
        var pdu = new RdCleanPathPdu();
        while (sequence.HasData)
        {
            var tag = sequence.PeekTag();
            if (tag.TagClass != TagClass.ContextSpecific)
                throw new AsnContentException("Unexpected tag in RDCleanPath PDU.");
            var field = sequence.ReadSequence(tag);
            pdu = tag.TagValue switch
            {
                0 => pdu with { Version = (long)field.ReadInteger() },
                1 => pdu with { Error = RdCleanPathError.Decode(field) },
                2 => pdu with { Destination = field.ReadCharacterString(UniversalTagNumber.UTF8String) },
                3 => pdu with { ProxyAuth = field.ReadCharacterString(UniversalTagNumber.UTF8String) },
                4 => pdu with { ServerAuth = field.ReadCharacterString(UniversalTagNumber.UTF8String) },
                5 => pdu with { PreconnectionBlob = field.ReadCharacterString(UniversalTagNumber.UTF8String) },
                6 => pdu with { X224ConnectionPdu = field.ReadOctetString() },
                7 => pdu with { ServerCertChain = ReadOctetStrings(field.ReadSequence()) },
                9 => pdu with { ServerAddr = field.ReadCharacterString(UniversalTagNumber.UTF8String) },
                _ => pdu, // unknown/unused optional field
            };
        }
        return pdu;
    }

    public byte[] Encode()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            Explicit(writer, 0, w => w.WriteInteger(Version));
            if (Error is not null)
                Explicit(writer, 1, Error.Encode);
            WriteString(writer, 2, Destination);
            WriteString(writer, 3, ProxyAuth);
            WriteString(writer, 4, ServerAuth);
            WriteString(writer, 5, PreconnectionBlob);
            if (X224ConnectionPdu is not null)
                Explicit(writer, 6, w => w.WriteOctetString(X224ConnectionPdu));
            if (ServerCertChain is not null)
            {
                Explicit(writer, 7, w =>
                {
                    using (w.PushSequence())
                    {
                        foreach (var cert in ServerCertChain)
                            w.WriteOctetString(cert);
                    }
                });
            }
            WriteString(writer, 9, ServerAddr);
        }
        return writer.Encode();
    }

    internal static void Explicit(AsnWriter writer, int tag, Action<AsnWriter> inner)
    {
        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, tag, isConstructed: true)))
            inner(writer);
    }

    private static void WriteString(AsnWriter writer, int tag, string? value)
    {
        if (value is not null)
            Explicit(writer, tag, w => w.WriteCharacterString(UniversalTagNumber.UTF8String, value));
    }

    private static List<byte[]> ReadOctetStrings(AsnReader reader)
    {
        var list = new List<byte[]>();
        while (reader.HasData)
            list.Add(reader.ReadOctetString());
        return list;
    }
}

public sealed record RdCleanPathError(int ErrorCode, int? HttpStatusCode = null, int? WsaLastError = null, int? TlsAlertCode = null)
{
    internal static RdCleanPathError Decode(AsnReader field)
    {
        var sequence = field.ReadSequence();
        int code = 0;
        int? http = null, wsa = null, tls = null;
        while (sequence.HasData)
        {
            var tag = sequence.PeekTag();
            var value = (int)sequence.ReadSequence(tag).ReadInteger();
            switch (tag.TagValue)
            {
                case 0: code = value; break;
                case 1: http = value; break;
                case 2: wsa = value; break;
                case 3: tls = value; break;
            }
        }
        return new RdCleanPathError(code, http, wsa, tls);
    }

    internal void Encode(AsnWriter writer)
    {
        using (writer.PushSequence())
        {
            RdCleanPathPdu.Explicit(writer, 0, w => w.WriteInteger(ErrorCode));
            if (HttpStatusCode is { } http)
                RdCleanPathPdu.Explicit(writer, 1, w => w.WriteInteger(http));
            if (WsaLastError is { } wsa)
                RdCleanPathPdu.Explicit(writer, 2, w => w.WriteInteger(wsa));
            if (TlsAlertCode is { } tls)
                RdCleanPathPdu.Explicit(writer, 3, w => w.WriteInteger(tls));
        }
    }
}
