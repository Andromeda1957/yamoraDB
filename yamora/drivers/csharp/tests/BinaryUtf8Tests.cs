using System.Text;
using Yamora;

namespace DriverTests;

static partial class Program
{
    static async Task BinaryUtf8Boundaries()
    {
        using var ca = new Certificates(); using var certificate = ca.Issue();
        var failures = new List<string>();
        foreach (var method in new[] { BinaryMethod.Put, BinaryMethod.Get })
        foreach (var valid in new[] { true, false })
        {
            // Byte 4095 is a UTF-8 leading byte in both cases; byte 4096 is
            // either its continuation or ASCII, never a second independent fault.
            var bytes = Encoding.ASCII.GetBytes("#" + new string('x', 4094))
                .Concat(valid ? Encoding.UTF8.GetBytes("é\nn: 1\n") : new byte[] { 0xc3, (byte)'x', 10 }).ToArray();
            await using var server = new BinaryServer(certificate, (s, r, ct) => BinaryFixtureWire.Reply(s, r, ct, source: bytes));
            using var db = Binary(server.Endpoint, ca.Root);
            var label = (valid ? "valid" : "malformed") + "-" + method.ToString().ToLowerInvariant();
            try
            {
                var response = await db.CallAsync(method, "allowed", "boundary", method == BinaryMethod.Put ? bytes : null);
                if (!valid)
                {
                    Check(server.Requests.Count == 1, "UTF8 fixture did not dispatch");
                    failures.Add(label + " accepted after exactly one dispatch");
                }
                else Check(response.StatusCode == (method == BinaryMethod.Put ? 201 : 200)
                    && (method == BinaryMethod.Put || response.Body.SequenceEqual(bytes)), "UTF8 valid response changed");
            }
            catch (BinaryException error)
            {
                if (valid)
                {
                    Check(error.Kind == BinaryFailure.Protocol && server.Requests.Count == (method == BinaryMethod.Put ? 0 : 1), "UTF8 infrastructure failure is not regression evidence");
                    failures.Add(label + " rejected with Protocol; dispatch=" + server.Requests.Count);
                }
                else Check(error.Kind == BinaryFailure.Protocol && server.Requests.Count == (method == BinaryMethod.Put ? 0 : 1), "malformed UTF8 rejected for a different reason");
            }
        }
        foreach (var failure in failures) Console.WriteLine("UTF8 RED " + failure);
        Check(failures.Count == 0, "UTF8 boundary behavior: " + string.Join("; ", failures));
    }
}
