using System.Security.Cryptography;
using Snowcap.TCrypt;

int passed = 0;
int failed = 0;

void Assert(bool condition, string name)
{
    if (condition) { Console.WriteLine($"  PASS: {name}"); passed++; }
    else { Console.WriteLine($"  FAIL: {name}"); failed++; }
}

// Generate a test key
byte[] key = RandomNumberGenerator.GetBytes(32);

Console.WriteLine("=== SuitcaseCrypt Library Tests (AES-256-GCM) ===");
Console.WriteLine();

// Test 1: Basic roundtrip
Console.WriteLine("1. Basic encrypt/decrypt roundtrip");
string original = "Server=db.local;Database=test;Password=Secret123!";
string encrypted = SuitcaseCrypt.Encrypt(original, key);
string decrypted = SuitcaseCrypt.Decrypt(encrypted, key);
Assert(decrypted == original, "Decrypted matches original");
Assert(encrypted != original, "Encrypted differs from original");

// Test 2: Per-value random nonce — same plaintext produces different ciphertext
Console.WriteLine("2. Per-value random nonce");
string encrypted2 = SuitcaseCrypt.Encrypt(original, key);
Assert(encrypted != encrypted2, "Same plaintext produces different ciphertext");

// Test 3: Output format — nonce[12] + ciphertext[n] + tag[16]
Console.WriteLine("3. Output format");
byte[] raw = Convert.FromBase64String(encrypted);
Assert(raw.Length >= 12 + 1 + 16, "Output contains nonce + ciphertext + tag");
// For GCM: ciphertext length == plaintext length (no padding), plus 12 nonce + 16 tag
int expectedLen = 12 + System.Text.Encoding.UTF8.GetByteCount(original) + 16;
Assert(raw.Length == expectedLen, $"Output length is {expectedLen} (12 nonce + {System.Text.Encoding.UTF8.GetByteCount(original)} ct + 16 tag)");

// Test 4: Empty string
Console.WriteLine("4. Empty string roundtrip");
string emptyEnc = SuitcaseCrypt.Encrypt("", key);
string emptyDec = SuitcaseCrypt.Decrypt(emptyEnc, key);
Assert(emptyDec == "", "Empty string roundtrip works");

// Test 5: Unicode
Console.WriteLine("5. Unicode roundtrip");
string unicode = "Héllo Wörld! 日本語テスト 🎉";
string unicodeEnc = SuitcaseCrypt.Encrypt(unicode, key);
string unicodeDec = SuitcaseCrypt.Decrypt(unicodeEnc, key);
Assert(unicodeDec == unicode, "Unicode roundtrip works");

// Test 6: Long string
Console.WriteLine("6. Long string roundtrip");
string longStr = new string('A', 10000);
string longEnc = SuitcaseCrypt.Encrypt(longStr, key);
string longDec = SuitcaseCrypt.Decrypt(longEnc, key);
Assert(longDec == longStr, "10K character roundtrip works");

// Test 7: Wrong key fails (GCM auth tag check)
Console.WriteLine("7. Wrong key fails");
byte[] wrongKey = RandomNumberGenerator.GetBytes(32);
try
{
    SuitcaseCrypt.Decrypt(encrypted, wrongKey);
    Assert(false, "Wrong key should throw");
}
catch (CryptographicException)
{
    Assert(true, "Wrong key throws CryptographicException");
}

// Test 8: Invalid key length
Console.WriteLine("8. Invalid key length");
try
{
    SuitcaseCrypt.Encrypt("test", new byte[16]);
    Assert(false, "16-byte key should throw");
}
catch (ArgumentException)
{
    Assert(true, "16-byte key throws ArgumentException");
}

// Test 9: Null inputs
Console.WriteLine("9. Null inputs");
try
{
    SuitcaseCrypt.Encrypt(null!, key);
    Assert(false, "Null plaintext should throw");
}
catch (ArgumentNullException)
{
    Assert(true, "Null plaintext throws ArgumentNullException");
}

// Test 10: Corrupted ciphertext (GCM detects tamper)
Console.WriteLine("10. Corrupted ciphertext");
try
{
    SuitcaseCrypt.Decrypt("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", key);
    Assert(false, "Corrupted data should throw");
}
catch
{
    Assert(true, "Corrupted data throws exception");
}

// Test 11: Tampered ciphertext — flip a byte (GCM auth tag rejects)
Console.WriteLine("11. Tampered ciphertext detected");
byte[] tampered = Convert.FromBase64String(encrypted);
tampered[14] ^= 0xFF; // flip a ciphertext byte
try
{
    SuitcaseCrypt.Decrypt(Convert.ToBase64String(tampered), key);
    Assert(false, "Tampered ciphertext should throw");
}
catch (CryptographicException)
{
    Assert(true, "Tampered ciphertext throws CryptographicException");
}

// Test 12: LoadKey without CREDENTIALS_DIRECTORY
Console.WriteLine("12. LoadKey without CREDENTIALS_DIRECTORY");
try
{
    Environment.SetEnvironmentVariable("CREDENTIALS_DIRECTORY", null);
    SuitcaseCrypt.LoadKey();
    Assert(false, "Missing CREDENTIALS_DIRECTORY should throw");
}
catch (InvalidOperationException)
{
    Assert(true, "Missing CREDENTIALS_DIRECTORY throws InvalidOperationException");
}

// Test 13: LoadKey with CREDENTIALS_DIRECTORY but missing file
Console.WriteLine("13. LoadKey with missing credential file");
try
{
    Environment.SetEnvironmentVariable("CREDENTIALS_DIRECTORY", "/tmp/nonexistent-cred-dir");
    SuitcaseCrypt.LoadKey();
    Assert(false, "Missing credential file should throw");
}
catch (FileNotFoundException)
{
    Assert(true, "Missing credential file throws FileNotFoundException");
}
finally
{
    Environment.SetEnvironmentVariable("CREDENTIALS_DIRECTORY", null);
}

Console.WriteLine();
Console.WriteLine($"=== Results: {passed} passed, {failed} failed ===");

return failed > 0 ? 1 : 0;
