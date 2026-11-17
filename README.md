# Rarebl PHP SDK

One file (`Rarebl.php`, namespace `Rarebl`), PHP 8.1+, `ext-gmp` (the optional `secp256k1` extension is used automatically for constant-time ECDSA signing). `ext-sodium` and `ext-openssl` are needed only for the hosted-signing envelope; `ext-curl` for the HTTP client. Builds, verifies and signs transactions **on your server**, so private keys never go to Rarebl or anyone else.

## Download

```bash
curl -fsSLO https://docs.rarebl.com/sdk/php/Rarebl.php
echo "5784caa72a1c89abd6a386911cac6008d8726757de3456e2606ff986592c142c  Rarebl.php" | sha256sum -c -
```

Checksums for all SDK files: `https://docs.rarebl.com/sdk/SHA256SUMS`. Then `require 'Rarebl.php';`. Or install it with Composer: `composer require rarebl/rarebl-php` (the same file, autoloaded). Check `php -m | grep -E 'gmp|curl'`.

## Send BTC

```php
require 'Rarebl.php';
use Rarebl\Rarebl;

$c = new Rarebl();                                   // https://api.rarebl.com
$key = trim(file_get_contents('/etc/myapp/btc.key')); // hex or WIF; never hard-code it
$txid = $c->transfer([
    'chain' => 'btc', 'from' => 'bc1q...sender', 'to' => 'bc1q...recipient',
    'amount' => '0.001', 'key' => $key, 'priority' => 'standard',
]);
```

`transfer` asks the API to build the transaction, **recomputes every digest locally and checks that it pays exactly what you asked**, signs on your machine, then assembles and broadcasts. BTC/LTC/BCH senders are watched automatically the first time.

## Send USDT on TRON

```php
$txid = $c->transfer([
    'chain' => 'tron', 'from' => 'T...sender', 'to' => 'T...recipient', 'amount' => '25',
    'token' => 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t', 'key' => getenv('TRON_KEY'),
    'maxFee' => 100000000,                            // feeLimit cap in sun
]);
```

USDT/USDC decimals are built in; pass `'decimals' => n` for other tokens. ETH works the same way.

## Keys, addresses, signing

```php
use Rarebl\{Keys, Address, Signer, Webhook, Envelope};

$k = Keys::generate('btc', 'p2tr');                  // privateKey, wif, publicKey, address, outputKey, type
Keys::fromPrivate('eth', '<64-hex>');
Address::derive('ltc', $pubkeyHex, 'p2wpkh');
Address::validate('bch', 'bitcoincash:q...');        // ['valid', 'type', 'normalized']

$build = $c->build(['chain' => 'btc', 'from' => [$addr], 'to' => [['address' => $to, 'amount' => '0.001']], 'priority' => 'fast']);
$expect = ['to' => ['address' => $to, 'amount' => '0.001']];
Signer::verifyBuild($build, null, $expect);          // throws VerifyException
$sigs = Signer::signBuild($build, $key, ['expect' => $expect]);   // expect is required
$c->assemble($build['unsigned'], $sigs, true);
Signer::signDigest($digestHex, $key, 'ecdsa-secp256k1', 1);   // DER+sighash | schnorr-bip340 | ecdsa-secp256k1-recoverable
```

Types: BTC/LTC `p2pkh`, `p2sh-p2wpkh`, `p2wpkh`, `p2tr`; BCH `p2pkh` (CashAddr, no prefix); DASH `p2pkh`; ETH; TRON. Exceptions: `ApiException` (`->apiCode`, `->reason`, `->detail`, `->httpStatus`), `VerifyException`, `KeyMismatchException`, `EnvelopeException`, all extending `RareblException`.

`Signer::signBuild($build, $keys, $opts)` takes `$opts = ['expect' => ..., 'unsafeNoExpect' => false, 'verify' => true, 'deterministic' => false, 'nowMs' => null, 'prevTxs' => null]` and throws `InputException` without `expect['to']`: without it nothing pins who is paid. `'unsafeNoExpect' => true` signs without pinning the recipients (the default fee caps still apply); `'verify' => false` also needs it. Legacy p2pkh inputs (btc, ltc, dash) must carry `unsigned.inputs[i].prevTx` (or pass `'prevTxs' => [txid => rawHex]`): the SDK checks that it hashes to the outpoint and takes the amount from it. `Signer::verifyBuild($build, $pubkeys, $expect, $nowMs, $prevTxs)`.

`expect` has the same shape as the JS SDK: `to` (`['address', 'amount' | 'amountRaw']` or a list), `change` (extra change addresses; input addresses always qualify), `token`, `decimals`, `opReturn`, `from`, `chain`, and fee caps `maxFee` (whole units), `maxFeeSats`, `maxFeeRaw` (ETH wei), `maxFeeLimit` (TRON sun). `amount: "max"` must leave no change output. Default caps when you give none: UTXO fee rate 1000 sat/vB (btc, ltc) or 50 sat/byte (bch, dash; override with `maxFeeRate` or an absolute `maxFee`); ETH `maxFeePerGas` 500 gwei (`maxFeePerGas`, wei), total fee 0.05 ETH (`maxFee`), tip at most max(5 gwei, maxFeePerGas/2) (`maxPriorityFeePerGas`, wei); TRON `feeLimit` 150 TRX (`maxFeeLimit`). A UTXO transaction with version other than 1 or 2, a non-zero locktime (`'allowLocktime' => true`) or a repeated outpoint is refused, and sighash `0x41` is accepted on bch only.

## Webhooks

```php
$ok = \Rarebl\Webhook::verify($signingSecret, file_get_contents('php://input'),
        $_SERVER['HTTP_X_RAREBL_SIGNATURE'] ?? '', 300);
if (!$ok) { http_response_code(400); exit; }
```

Use the **raw** body. It checks `t=<unix>,v1=<hex HMAC-SHA256(secret, t . "." . body)>` with `hash_equals`, accepts several `v1` values (secret rotation) and rejects stale timestamps (`$toleranceSec` 0 or null turns the age check off; a malformed header returns `false`).

## Security

- **Why local signing.** A private key sent to a server is a key that server, and anything on the path to it, can use. Here the API sees only public data and finished signatures: Rarebl cannot spend your funds, and a breach of Rarebl cannot leak your keys.
- **`verify` is on by default and `expect` is required.** `signBuild` / `transfer` refuse to sign a digest they cannot recompute from the unsigned transaction (legacy, BIP143, BIP341, BCH FORKID, EIP-1559, TRON txID), and refuse a transaction that pays a different recipient or amount than `expect`/`transfer` say, sends change anywhere but back to you, or has an unreasonable fee. Without it a compromised or buggy server could make you sign a payment to someone else. `'verify' => false` signs whatever digest it is given and needs `'unsafeNoExpect' => true`.
- **Hosted signing.** Hosted signing sends your private key to Rarebl over TLS. Signing locally with an SDK keeps keys on your side and is recommended. `Envelope::encrypt($signerKey, $payload)` builds an envelope v2 (X25519 via sodium, HKDF-SHA256, AES-256-GCM via OpenSSL) for `tx/sign` / `tx/send`: `$payload` is `['privateKeys' => [...], 'op' => 'sign', 'chain' => 'btc', 'digests' => [...]]` or `['op' => 'send', 'bind' => Envelope::bindOf('btc', ['address' => $to, 'amount' => '0.001']), ...]`, valid for at most 300 seconds, one use. The request needs the header `X-Rarebl-Accept-Risk: hosted-signing`. `Envelope::decrypt` opens address/new replies sealed to your `encryptTo` key.
- **Constant-time only with the `secp256k1` extension.** Without it the secp256k1 and Schnorr code runs on GMP: correct (RFC 6979, BIP340 vectors) but **not constant-time**, so it leaks timing information. If the `secp256k1` PHP extension (libsecp256k1 bindings) is loaded, ECDSA signing and public-key derivation use it automatically (`Secp::backend()` tells which; `RAREBL_PURE_PHP=1` forces the pure path); Schnorr (p2tr) signing always runs on GMP. Use it on a machine you control, not shared hosting or hosts where an attacker can run code beside you.
- ECDSA is RFC 6979, low-S, and every signature is verified after signing. BIP340 (p2tr) signatures use fresh random aux randomness; pass `'deterministic' => true` for reproducible output.
- Test keys in this repository are labelled TEST ONLY and are public. Never fund them.

## Tests

`php tests/run.php` (no Composer). If your PHP loads gmp/sodium as shared extensions: `php -d extension=gmp -d extension=sodium tests/run.php`. It checks RFC 6979 and BIP340 vectors, BIP143/BIP341 digests, addresses for every chain, the shared vectors in `sdk/vectors/` (including the Python SDK's signatures byte for byte), the envelopes and the webhook rules.
