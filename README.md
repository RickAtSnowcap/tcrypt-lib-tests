# tcrypt-lib-tests

Tests for [tcrypt-lib](https://github.com/RickAtSnowcap/tcrypt-lib), Snowcap TCrypt's AES-256-GCM
library for .NET. It's a small console program: 13 test groups with 15 checks.

| # | What it checks |
| --- | --- |
| 1 | Encrypt/decrypt round trip |
| 2 | A random nonce per value: the same plaintext encrypts differently each time |
| 3 | Output format: nonce (12 bytes) + ciphertext + tag (16 bytes), Base64-encoded |
| 4–6 | Empty, Unicode and 10,000-character strings |
| 7 | The wrong key is rejected |
| 8 | Keys that aren't 32 bytes are rejected |
| 9 | Null input is rejected |
| 10–11 | Corrupted or tampered ciphertext is rejected by the GCM tag |
| 12–13 | `LoadKey()` fails clearly without `CREDENTIALS_DIRECTORY` or without the credential file |

## Run

Clone it next to tcrypt-lib (the project references `../tcrypt-lib`), then:

```bash
dotnet run
```

It needs the .NET 10 SDK. It prints PASS or FAIL for each check and exits with 1 if anything failed.

## License

MIT. See [LICENSE](LICENSE).
