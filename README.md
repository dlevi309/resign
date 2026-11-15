# resign

`resign` ad-hoc signs a Mach-O binary in place using Apple's Security framework (`SecCodeSigner`), the same machinery behind `codesign`. It runs on iOS and macOS.

By default it keeps the binary's existing identifier, requirements, entitlements and resource rules. You can override the entitlements or the identifier with the options below.

## Usage

```
resign [-v] [-e <plist>] [-i <identifier>] <input_file>
```

| Argument | Description |
| --- | --- |
| `-v` | Verbose output. Prints the new signing information, or the error if signing fails. |
| `-e <plist>` | Replaces the binary's entitlements with the ones in this plist file. |
| `-i <identifier>` | Sets the code signing identifier, replacing the existing one. |
| `<input_file>` | The Mach-O file to sign. It must be the last argument. |

### Examples

```sh
# Re-sign, keeping the existing metadata
resign /path/to/binary

# Re-sign with new entitlements and a new identifier
resign -v -e ent.xml -i com.example.tool /path/to/binary
```

If signing fails while resigning an app (`Example.app/Example`) make sure you remove the preexisting _CodeSignature directory (`Example.app/_CodeSignature`)

## Building

```sh
make
```

## Credits

| Project | Notes |
| --- | --- |
| [fastPathSign](https://github.com/opa334/TrollStore/blob/main/Exploits/fastPathSign/src/codesign.m) from [TrollStore](https://github.com/opa334/TrollStore) by [alfiecg24](https://github.com/alfiecg24) and [opa334](https://github.com/opa334) | `resign` is a light shim that wraps over fastPathSign's `codesign.m`. TrollStore's license is included in [LICENSE](LICENSE). |
