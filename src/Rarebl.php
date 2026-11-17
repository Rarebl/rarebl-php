<?php
/**
 * Rarebl signing SDK for PHP: build, verify and sign transactions locally.
 *
 * Single file, PHP >= 8.1, ext-gmp.  ext-sodium + ext-openssl are needed only for the
 * hosted-signing envelope; ext-curl for the HTTP client.
 * Spec: api/sdk/README.md and api/open/CONTRACT-v2.md.
 *
 * Private keys never leave this process.  The only code that can send a key anywhere is
 * Envelope::encrypt (the hosted-signing helper, which sends the key to Rarebl over TLS; local
 * signing is recommended), and only if you call it.
 *
 * SECURITY NOTE: by default this is pure-PHP crypto on GMP.  It is NOT constant-time and gives
 * no protection against local side-channel attacks.  If the `secp256k1` PHP extension
 * (libsecp256k1 bindings) is loaded, ECDSA signing and public-key derivation use it
 * automatically (constant-time); Schnorr (p2tr) signing stays pure PHP.  Set the environment
 * variable RAREBL_PURE_PHP=1 to force the pure path.  Use the SDK on a machine you control,
 * not on a shared host.
 *
 *     require 'Rarebl.php';
 *     $k = \Rarebl\Keys::generate('btc', 'p2wpkh');                 // local, CSPRNG
 *     $c = new \Rarebl\Rarebl();
 *     $txid = $c->transfer(['chain' => 'btc', 'from' => $k['address'], 'to' => 'bc1q...',
 *                           'amount' => '0.001', 'key' => $k['privateKey'], 'priority' => 'standard']);
 */

declare(strict_types=1);

namespace Rarebl;

use GMP;

const VERSION = '0.2.0';

// ---------------------------------------------------------------------------------------
// errors

class RareblException extends \RuntimeException
{
}

/** The API answered with an error envelope: code, reason and detail are exposed. */
class ApiException extends RareblException
{
    public function __construct(
        public readonly string $apiCode,
        string $message = '',
        public readonly ?string $reason = null,
        public readonly ?string $detail = null,
        public readonly ?int $httpStatus = null,
        public readonly mixed $data = null,
    ) {
        parent::__construct(implode(': ', array_filter([$apiCode, $reason, $message, $detail], fn($x) => $x !== null && $x !== '')));
    }
}

/** A build reply failed local verification.  Nothing was signed. */
class VerifyException extends RareblException
{
}

/** No supplied key derives the address a digest belongs to. */
class KeyMismatchException extends RareblException
{
}

class InputException extends RareblException
{
}

class EnvelopeException extends RareblException
{
}

// ---------------------------------------------------------------------------------------
// hashing

final class Hash
{
    public static function sha256(string $b): string
    {
        return hash('sha256', $b, true);
    }

    public static function dsha256(string $b): string
    {
        return hash('sha256', hash('sha256', $b, true), true);
    }

    public static function hash160(string $b): string
    {
        return hash('ripemd160', hash('sha256', $b, true), true);
    }

    public static function tagged(string $tag, string $msg): string
    {
        $th = hash('sha256', $tag, true);
        return hash('sha256', $th . $th . $msg, true);
    }

    private static ?array $rc = null;

    /** Keccak-256 (original Keccak padding 0x01, as Ethereum uses; NOT PHP's sha3-256). */
    public static function keccak256(string $data): string
    {
        if (self::$rc === null) {
            $rc = [];
            $R = 1;
            for ($t = 0; $t < 24; $t++) {
                $v = 0;
                for ($j = 0; $j < 7; $j++) {
                    $R = (($R << 1) ^ (($R >> 7) * 0x71)) % 256;
                    if ($R & 2) {
                        $v ^= 1 << ((1 << $j) - 1);   // bit 63 lands on the sign bit: fine
                    }
                }
                $rc[] = $v;
            }
            self::$rc = $rc;
        }
        $rate = 136;
        $msg = $data . "\x01";
        $pad = (-strlen($msg)) % $rate;
        if ($pad < 0) {
            $pad += $rate;
        }
        $msg .= str_repeat("\x00", $pad);
        $msg[strlen($msg) - 1] = chr(ord($msg[strlen($msg) - 1]) | 0x80);
        $A = array_fill(0, 25, 0);
        for ($off = 0; $off < strlen($msg); $off += $rate) {
            $blk = array_values(unpack('P17', substr($msg, $off, $rate)));
            for ($i = 0; $i < 17; $i++) {
                $A[$i] ^= $blk[$i];
            }
            $A = self::f($A);
        }
        return pack('P4', $A[0], $A[1], $A[2], $A[3]);
    }

    private static function rol(int $x, int $n): int
    {
        if ($n === 0) {
            return $x;
        }
        return ($x << $n) | (($x >> (64 - $n)) & ((1 << $n) - 1));
    }

    private static function f(array $A): array
    {
        for ($rnd = 0; $rnd < 24; $rnd++) {
            $C = [];
            for ($x = 0; $x < 5; $x++) {
                $C[$x] = $A[$x] ^ $A[$x + 5] ^ $A[$x + 10] ^ $A[$x + 15] ^ $A[$x + 20];
            }
            $D = [];
            for ($x = 0; $x < 5; $x++) {
                $D[$x] = $C[($x + 4) % 5] ^ self::rol($C[($x + 1) % 5], 1);
            }
            for ($i = 0; $i < 25; $i++) {
                $A[$i] ^= $D[$i % 5];
            }
            $x = 1;
            $y = 0;
            $cur = $A[1];
            for ($t = 0; $t < 24; $t++) {
                [$x, $y] = [$y, (2 * $x + 3 * $y) % 5];
                $n = (($t + 1) * ($t + 2) / 2) % 64;
                $tmp = $A[$x + 5 * $y];
                $A[$x + 5 * $y] = self::rol($cur, (int)$n);
                $cur = $tmp;
            }
            for ($y = 0; $y < 5; $y++) {
                $T = array_slice($A, 5 * $y, 5);
                for ($x = 0; $x < 5; $x++) {
                    $A[$x + 5 * $y] = $T[$x] ^ (~$T[($x + 1) % 5] & $T[($x + 2) % 5]);
                }
            }
            $A[0] ^= self::$rc[$rnd];
        }
        return $A;
    }
}

// ---------------------------------------------------------------------------------------
// misc helpers

final class U
{
    public static function unhex(mixed $s, string $name = 'hex'): string
    {
        if (!is_string($s)) {
            throw new RareblException("$name must be a hex string");
        }
        if (str_starts_with($s, '0x') || str_starts_with($s, '0X')) {
            $s = substr($s, 2);
        }
        if (strlen($s) % 2 !== 0 || ($s !== '' && !ctype_xdigit($s))) {
            throw new RareblException("$name is not valid hex");
        }
        return (string)hex2bin($s);
    }

    public static function b64u(string $b): string
    {
        return rtrim(strtr(base64_encode($b), '+/', '-_'), '=');
    }

    public static function b64uDec(string $s): string
    {
        $r = base64_decode(strtr(trim($s), '-_', '+/') . str_repeat('=', (4 - strlen(trim($s)) % 4) % 4), true);
        if ($r === false) {
            throw new RareblException('invalid base64url');
        }
        return $r;
    }

    public static function g(string $hex): GMP
    {
        return gmp_init($hex === '' ? '0' : $hex, 16);
    }

    public static function bytesToG(string $b): GMP
    {
        return $b === '' ? gmp_init(0) : gmp_init(bin2hex($b), 16);
    }

    public static function gToBytes(GMP $v, int $len = 32): string
    {
        $h = gmp_strval($v, 16);
        if (strlen($h) % 2) {
            $h = '0' . $h;
        }
        $b = (string)hex2bin($h);
        if ($len > 0) {
            if (strlen($b) > $len) {
                throw new RareblException('integer too large');
            }
            $b = str_pad($b, $len, "\x00", STR_PAD_LEFT);
        }
        return $b;
    }

    /** minimal big-endian bytes ('' for zero) */
    public static function gMin(GMP $v): string
    {
        return gmp_cmp($v, 0) === 0 ? '' : self::gToBytes($v, 0);
    }

    public static function varint(int $n): string
    {
        if ($n < 0xFD) {
            return chr($n);
        }
        if ($n <= 0xFFFF) {
            return "\xfd" . pack('v', $n);
        }
        if ($n <= 0xFFFFFFFF) {
            return "\xfe" . pack('V', $n);
        }
        return "\xff" . pack('P', $n);
    }

    /** Number from JSON: int, decimal string, or 0x-hex string. */
    public static function num(mixed $v, string $name = 'number'): GMP
    {
        if (is_int($v)) {
            return gmp_init($v);
        }
        if (is_string($v)) {
            $s = trim($v);
            if (preg_match('/^0[xX][0-9a-fA-F]+$/', $s)) {
                return gmp_init(substr($s, 2), 16);
            }
            if (preg_match('/^[0-9]+$/', $s)) {
                return gmp_init($s, 10);
            }
        }
        throw new VerifyException("$name is not a number");
    }

    /** "0.0015" with 8 decimals -> GMP 150000 (exact; refuses extra decimals). */
    public static function units(string|int|float $amount, int $decimals): GMP
    {
        $a = is_float($amount) ? rtrim(rtrim(sprintf('%.' . $decimals . 'F', $amount), '0'), '.') : (string)$amount;
        if (!preg_match('/^([0-9]+)(?:\.([0-9]+))?$/', $a, $m)) {
            throw new VerifyException("bad amount '$a'");
        }
        $frac = $m[2] ?? '';
        if (strlen(rtrim($frac, '0')) > $decimals) {
            throw new VerifyException("amount $a has too many decimals");
        }
        $frac = str_pad(substr($frac, 0, $decimals), $decimals, '0');
        return gmp_init($m[1] . $frac, 10);
    }

    public static function randomBytes(int $n): string
    {
        return random_bytes($n);
    }
}

// ---------------------------------------------------------------------------------------
// secp256k1 on GMP (Jacobian coordinates; not constant-time)

final class Secp
{
    public static GMP $P;
    public static GMP $N;
    public static GMP $HALF;
    public static array $G;
    private static bool $ready = false;

    public static function init(): void
    {
        if (self::$ready) {
            return;
        }
        if (!extension_loaded('gmp')) {
            throw new RareblException('ext-gmp is required');
        }
        self::$P = gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 16);
        self::$N = gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16);
        self::$HALF = self::$N >> 1;
        self::$G = [
            gmp_init('79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798', 16),
            gmp_init('483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8', 16),
        ];
        self::$ready = true;
    }

    private static function inf(): array
    {
        return [gmp_init(0), gmp_init(1), gmp_init(0)];
    }

    private static function dbl(array $p): array
    {
        [$X, $Y, $Z] = $p;
        $P = self::$P;
        if (gmp_sign($Z) === 0 || gmp_sign($Y) === 0) {
            return self::inf();
        }
        $A = gmp_mod($X * $X, $P);
        $B = gmp_mod($Y * $Y, $P);
        $C = gmp_mod($B * $B, $P);
        $D = gmp_mod(2 * (($X + $B) * ($X + $B) - $A - $C), $P);
        $E = 3 * $A;
        $F = gmp_mod($E * $E, $P);
        $X3 = gmp_mod($F - 2 * $D, $P);
        return [$X3, gmp_mod($E * ($D - $X3) - 8 * $C, $P), gmp_mod(2 * $Y * $Z, $P)];
    }

    private static function add(array $p, array $q): array
    {
        [$X1, $Y1, $Z1] = $p;
        [$X2, $Y2, $Z2] = $q;
        $P = self::$P;
        if (gmp_sign($Z1) === 0) {
            return $q;
        }
        if (gmp_sign($Z2) === 0) {
            return $p;
        }
        $Z1Z1 = gmp_mod($Z1 * $Z1, $P);
        $Z2Z2 = gmp_mod($Z2 * $Z2, $P);
        $U1 = gmp_mod($X1 * $Z2Z2, $P);
        $U2 = gmp_mod($X2 * $Z1Z1, $P);
        $S1 = gmp_mod($Y1 * $Z2 * $Z2Z2, $P);
        $S2 = gmp_mod($Y2 * $Z1 * $Z1Z1, $P);
        if (gmp_cmp($U1, $U2) === 0) {
            return gmp_cmp($S1, $S2) === 0 ? self::dbl($p) : self::inf();
        }
        $H = gmp_mod($U2 - $U1, $P);
        $I = gmp_mod(4 * $H * $H, $P);
        $J = gmp_mod($H * $I, $P);
        $r = gmp_mod(2 * ($S2 - $S1), $P);
        $V = gmp_mod($U1 * $I, $P);
        $X3 = gmp_mod($r * $r - $J - 2 * $V, $P);
        $Y3 = gmp_mod($r * ($V - $X3) - 2 * $S1 * $J, $P);
        $Z3 = gmp_mod((($Z1 + $Z2) * ($Z1 + $Z2) - $Z1Z1 - $Z2Z2) * $H, $P);
        return [$X3, $Y3, $Z3];
    }

    private static function affine(array $p): ?array
    {
        [$X, $Y, $Z] = $p;
        if (gmp_sign($Z) === 0) {
            return null;
        }
        $zi = gmp_invert($Z, self::$P);
        $zi2 = gmp_mod($zi * $zi, self::$P);
        return [gmp_mod($X * $zi2, self::$P), gmp_mod($Y * $zi2 * $zi, self::$P)];
    }

    /** k * pt (affine [x,y] or null) -> affine or null */
    public static function mul(GMP $k, ?array $pt): ?array
    {
        if ($pt === null) {
            return null;
        }
        $k = gmp_mod($k, self::$N);
        if (gmp_sign($k) === 0) {
            return null;
        }
        $base = [$pt[0], $pt[1], gmp_init(1)];
        $tbl = [self::inf(), $base];
        for ($i = 2; $i < 16; $i++) {
            $tbl[$i] = self::add($tbl[$i - 1], $base);
        }
        $bits = strlen(gmp_strval($k, 2));
        $acc = self::inf();
        for ($shift = (intdiv($bits + 3, 4) - 1) * 4; $shift >= 0; $shift -= 4) {
            for ($i = 0; $i < 4; $i++) {
                $acc = self::dbl($acc);
            }
            $d = gmp_intval(($k >> $shift) & 15);
            if ($d) {
                $acc = self::add($acc, $tbl[$d]);
            }
        }
        return self::affine($acc);
    }

    public static function addAff(?array $a, ?array $b): ?array
    {
        if ($a === null) {
            return $b;
        }
        if ($b === null) {
            return $a;
        }
        return self::affine(self::add([$a[0], $a[1], gmp_init(1)], [$b[0], $b[1], gmp_init(1)]));
    }

    public static function neg(array $pt): array
    {
        return [$pt[0], self::$P - $pt[1]];
    }

    public static function onCurve(array $pt): bool
    {
        return gmp_sign(gmp_mod($pt[1] * $pt[1] - $pt[0] ** 3 - 7, self::$P)) === 0;
    }

    /** even-y point for x, or null */
    public static function liftX(GMP $x): ?array
    {
        if (gmp_cmp($x, self::$P) >= 0 || gmp_sign($x) < 0) {
            return null;
        }
        $y2 = gmp_mod($x ** 3 + 7, self::$P);
        $y = gmp_powm($y2, (self::$P + 1) >> 2, self::$P);
        if (gmp_cmp(gmp_mod($y * $y, self::$P), $y2) !== 0) {
            return null;
        }
        return [$x, gmp_testbit($y, 0) ? self::$P - $y : $y];
    }

    public static function serCompressed(array $pt): string
    {
        return chr(2 + (gmp_testbit($pt[1], 0) ? 1 : 0)) . U::gToBytes($pt[0]);
    }

    public static function serUncompressed(array $pt): string
    {
        return "\x04" . U::gToBytes($pt[0]) . U::gToBytes($pt[1]);
    }

    public static function parsePub(string $b): array
    {
        $n = strlen($b);
        if ($n === 33 && ($b[0] === "\x02" || $b[0] === "\x03")) {
            $pt = self::liftX(U::bytesToG(substr($b, 1)));
            if ($pt === null) {
                throw new RareblException('invalid public key');
            }
            if (($b[0] === "\x03") !== gmp_testbit($pt[1], 0)) {
                $pt = self::neg($pt);
            }
            return $pt;
        }
        if ($n === 65 && $b[0] === "\x04") {
            $pt = [U::bytesToG(substr($b, 1, 32)), U::bytesToG(substr($b, 33))];
            if (!self::onCurve($pt)) {
                throw new RareblException('invalid public key');
            }
            return $pt;
        }
        if ($n === 32) {
            $pt = self::liftX(U::bytesToG($b));
            if ($pt === null) {
                throw new RareblException('invalid public key');
            }
            return $pt;
        }
        throw new RareblException('invalid public key length');
    }

    public static function checkScalar(GMP $d): GMP
    {
        if (gmp_cmp($d, 1) < 0 || gmp_cmp($d, self::$N) >= 0) {
            throw new RareblException('private key out of range');
        }
        return $d;
    }

    /** @var mixed false = not checked yet, null = unavailable, otherwise a libsecp256k1 context */
    private static mixed $ctx = false;

    /** libsecp256k1 context from the optional `secp256k1` extension (constant-time), or null. */
    private static function ctx(): mixed
    {
        if (self::$ctx === false) {
            self::$ctx = null;
            if (!getenv('RAREBL_PURE_PHP') && function_exists('secp256k1_context_create') && defined('SECP256K1_CONTEXT_SIGN')) {
                try {
                    self::$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
                } catch (\Throwable) {
                    self::$ctx = null;
                }
            }
        }
        return self::$ctx;
    }

    /** 'secp256k1-ext' (constant-time libsecp256k1) or 'pure-php' (not constant-time). */
    public static function backend(): string
    {
        return self::ctx() !== null ? 'secp256k1-ext' : 'pure-php';
    }

    /** Compressed public key through the extension, or null (not available / any failure: the pure path is used). */
    private static function extPub(GMP $d): ?string
    {
        $ctx = self::ctx();
        if ($ctx === null) {
            return null;
        }
        try {
            $pub = null;
            $out = '';
            if (secp256k1_ec_pubkey_create($ctx, $pub, U::gToBytes($d)) !== 1) {
                return null;
            }
            secp256k1_ec_pubkey_serialize($ctx, $out, $pub, SECP256K1_EC_COMPRESSED);
            return is_string($out) && strlen($out) === 33 ? $out : null;
        } catch (\Throwable) {
            return null;
        }
    }

    /** d*G as an affine point (secret-dependent: extension when available). */
    public static function pubPoint(GMP $d): array
    {
        self::checkScalar($d);
        $c = self::extPub($d);
        return $c !== null ? self::parsePub($c) : self::mul($d, self::$G);
    }

    public static function pubkeyCreate(GMP $d): string
    {
        self::checkScalar($d);
        return self::extPub($d) ?? self::serCompressed(self::mul($d, self::$G));
    }

    /** RFC 6979 candidate nonces (HMAC-SHA256) */
    private static function rfc6979(GMP $d, string $h32): \Generator
    {
        $x = U::gToBytes($d);
        $h1 = U::gToBytes(gmp_mod(U::bytesToG($h32), self::$N));
        $V = str_repeat("\x01", 32);
        $K = str_repeat("\x00", 32);
        $K = hash_hmac('sha256', $V . "\x00" . $x . $h1, $K, true);
        $V = hash_hmac('sha256', $V, $K, true);
        $K = hash_hmac('sha256', $V . "\x01" . $x . $h1, $K, true);
        $V = hash_hmac('sha256', $V, $K, true);
        while (true) {
            $V = hash_hmac('sha256', $V, $K, true);
            $k = U::bytesToG($V);
            if (gmp_cmp($k, 1) >= 0 && gmp_cmp($k, self::$N) < 0) {
                yield $k;
            }
            $K = hash_hmac('sha256', $V . "\x00", $K, true);
            $V = hash_hmac('sha256', $V, $K, true);
        }
    }

    /** RFC 6979 deterministic ECDSA, low-S.  Returns [r, s, recid]. */
    public static function ecdsaSign(string $h32, GMP $d): array
    {
        if (strlen($h32) !== 32) {
            throw new RareblException('digest must be 32 bytes');
        }
        self::checkScalar($d);
        $ctx = self::ctx();
        if ($ctx !== null) {
            try {
                $rsig = null;
                $ser = '';
                $recid = 0;
                if (secp256k1_ecdsa_sign_recoverable($ctx, $rsig, $h32, U::gToBytes($d)) === 1) {
                    secp256k1_ecdsa_recoverable_signature_serialize_compact($ctx, $ser, $recid, $rsig);
                    if (is_string($ser) && strlen($ser) === 64) {
                        $r = U::bytesToG(substr($ser, 0, 32));
                        $s = U::bytesToG(substr($ser, 32, 32));
                        if (self::ecdsaVerify($h32, $r, $s, self::pubPoint($d))) {  // public-data check; the pure path takes over on any doubt
                            return [$r, $s, (int)$recid];
                        }
                    }
                }
            } catch (\Throwable) {
                // fall through to the pure implementation
            }
        }
        $z = U::bytesToG($h32);
        foreach (self::rfc6979($d, $h32) as $k) {
            $R = self::mul($k, self::$G);
            $r = gmp_mod($R[0], self::$N);
            if (gmp_sign($r) === 0) {
                continue;
            }
            $s = gmp_mod(gmp_invert($k, self::$N) * ($z + $r * $d), self::$N);
            if (gmp_sign($s) === 0) {
                continue;
            }
            $recid = (gmp_testbit($R[1], 0) ? 1 : 0) | (gmp_cmp($R[0], self::$N) >= 0 ? 2 : 0);
            if (gmp_cmp($s, self::$HALF) > 0) {
                $s = self::$N - $s;
                $recid ^= 1;
            }
            return [$r, $s, $recid];
        }
        throw new RareblException('unreachable');
    }

    public static function ecdsaVerify(string $h32, GMP $r, GMP $s, array $pub): bool
    {
        $N = self::$N;
        if (gmp_cmp($r, 1) < 0 || gmp_cmp($r, $N) >= 0 || gmp_cmp($s, 1) < 0 || gmp_cmp($s, $N) >= 0) {
            return false;
        }
        $z = U::bytesToG($h32);
        $w = gmp_invert($s, $N);
        $pt = self::addAff(self::mul(gmp_mod($z * $w, $N), self::$G), self::mul(gmp_mod($r * $w, $N), $pub));
        return $pt !== null && gmp_cmp(gmp_mod($pt[0], $N), $r) === 0;
    }

    public static function ecdsaRecover(string $h32, GMP $r, GMP $s, int $recid): array
    {
        $x = $r + (($recid & 2) ? self::$N : 0);
        $pt = self::liftX($x);
        if ($pt === null) {
            throw new RareblException('bad signature');
        }
        if (gmp_testbit($pt[1], 0) !== (bool)($recid & 1)) {
            $pt = self::neg($pt);
        }
        $z = U::bytesToG($h32);
        $ri = gmp_invert($r, self::$N);
        $a = self::mul(gmp_mod($s * $ri, self::$N), $pt);
        $b = self::mul(gmp_mod(-$z * $ri, self::$N), self::$G);
        $q = self::addAff($a, $b);
        if ($q === null) {
            throw new RareblException('bad signature');
        }
        return $q;
    }

    private static function derInt(GMP $v): string
    {
        $b = U::gToBytes($v, 0);
        if (ord($b[0]) & 0x80) {
            $b = "\x00" . $b;
        }
        return "\x02" . chr(strlen($b)) . $b;
    }

    public static function derEncode(GMP $r, GMP $s): string
    {
        $body = self::derInt($r) . self::derInt($s);
        return "\x30" . chr(strlen($body)) . $body;
    }

    /** @return array{0: GMP, 1: GMP} */
    public static function derDecode(string $sig): array
    {
        if (strlen($sig) < 8 || $sig[0] !== "\x30" || ord($sig[1]) !== strlen($sig) - 2 || $sig[2] !== "\x02") {
            throw new RareblException('bad DER');
        }
        $lr = ord($sig[3]);
        $r = U::bytesToG(substr($sig, 4, $lr));
        if ($sig[4 + $lr] !== "\x02") {
            throw new RareblException('bad DER');
        }
        $ls = ord($sig[5 + $lr]);
        return [$r, U::bytesToG(substr($sig, 6 + $lr, $ls))];
    }

    // --- BIP340 Schnorr -----------------------------------------------------------------

    /**
     * BIP340 signature.  $aux (32 bytes) defaults to fresh random bytes; pass str_repeat("\x00", 32) for
     * deterministic, reproducible output (what the test vectors use).  Always pure PHP.
     */
    public static function schnorrSign(string $msg32, GMP $d, ?string $aux = null): string
    {
        $aux ??= random_bytes(32);
        if (strlen($msg32) !== 32 || strlen($aux) !== 32) {
            throw new RareblException('msg and aux must be 32 bytes');
        }
        self::checkScalar($d);
        $pt = self::mul($d, self::$G);
        if (gmp_testbit($pt[1], 0)) {
            $d = self::$N - $d;
        }
        $px = U::gToBytes($pt[0]);
        $t = U::gToBytes($d ^ U::bytesToG(Hash::tagged('BIP0340/aux', $aux)));
        $k = gmp_mod(U::bytesToG(Hash::tagged('BIP0340/nonce', $t . $px . $msg32)), self::$N);
        if (gmp_sign($k) === 0) {
            throw new RareblException('schnorr nonce failure');
        }
        $R = self::mul($k, self::$G);
        if (gmp_testbit($R[1], 0)) {
            $k = self::$N - $k;
        }
        $rx = U::gToBytes($R[0]);
        $e = gmp_mod(U::bytesToG(Hash::tagged('BIP0340/challenge', $rx . $px . $msg32)), self::$N);
        $sig = $rx . U::gToBytes(gmp_mod($k + $e * $d, self::$N));
        if (!self::schnorrVerify($msg32, $sig, $px)) {
            throw new RareblException('schnorr self-verification failed');
        }
        return $sig;
    }

    public static function schnorrVerify(string $msg32, string $sig, string $xonly): bool
    {
        if (strlen($sig) !== 64 || strlen($xonly) !== 32 || strlen($msg32) !== 32) {
            return false;
        }
        $pt = self::liftX(U::bytesToG($xonly));
        $r = U::bytesToG(substr($sig, 0, 32));
        $s = U::bytesToG(substr($sig, 32));
        if ($pt === null || gmp_cmp($r, self::$P) >= 0 || gmp_cmp($s, self::$N) >= 0) {
            return false;
        }
        $e = gmp_mod(U::bytesToG(Hash::tagged('BIP0340/challenge', substr($sig, 0, 32) . $xonly . $msg32)), self::$N);
        $R = self::addAff(self::mul($s, self::$G), self::mul(self::$N - $e, $pt));
        return $R !== null && !gmp_testbit($R[1], 0) && gmp_cmp($R[0], $r) === 0;
    }

    /** BIP341 output key (x-only) for a key-path-only taproot output. */
    public static function taprootTweakPub(string $internalXonly, string $merkleRoot = ''): string
    {
        $pt = self::liftX(U::bytesToG($internalXonly));
        if ($pt === null) {
            throw new RareblException('invalid x-only key');
        }
        $t = U::bytesToG(Hash::tagged('TapTweak', $internalXonly . $merkleRoot));
        if (gmp_cmp($t, self::$N) >= 0) {
            throw new RareblException('tweak out of range');
        }
        $q = self::addAff($pt, self::mul($t, self::$G));
        return U::gToBytes($q[0]);
    }

    public static function taprootTweakSecret(GMP $d, string $merkleRoot = ''): GMP
    {
        $pt = self::mul($d, self::$G);
        if (gmp_testbit($pt[1], 0)) {
            $d = self::$N - $d;
        }
        $t = U::bytesToG(Hash::tagged('TapTweak', U::gToBytes($pt[0]) . $merkleRoot));
        return gmp_mod($d + $t, self::$N);
    }
}

// ---------------------------------------------------------------------------------------
// Base58, Bech32/Bech32m, CashAddr

final class Codec
{
    private const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    private const BECH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

    public static function b58encode(string $b): string
    {
        $n = U::bytesToG($b);
        $out = '';
        while (gmp_sign($n) > 0) {
            [$n, $r] = gmp_div_qr($n, 58);
            $out = self::B58[gmp_intval($r)] . $out;
        }
        $pad = strlen($b) - strlen(ltrim($b, "\x00"));
        return str_repeat('1', $pad) . $out;
    }

    public static function b58decode(string $s): string
    {
        $n = gmp_init(0);
        for ($i = 0, $l = strlen($s); $i < $l; $i++) {
            $p = strpos(self::B58, $s[$i]);
            if ($p === false) {
                throw new RareblException('invalid base58 character');
            }
            $n = $n * 58 + $p;
        }
        $raw = gmp_sign($n) === 0 ? '' : U::gToBytes($n, 0);
        return str_repeat("\x00", strlen($s) - strlen(ltrim($s, '1'))) . $raw;
    }

    public static function b58checkEncode(string $payload): string
    {
        return self::b58encode($payload . substr(Hash::dsha256($payload), 0, 4));
    }

    public static function b58checkDecode(string $s): string
    {
        $raw = self::b58decode($s);
        if (strlen($raw) < 5 || substr(Hash::dsha256(substr($raw, 0, -4)), 0, 4) !== substr($raw, -4)) {
            throw new RareblException('bad base58 checksum');
        }
        return substr($raw, 0, -4);
    }

    private static function bechPolymod(array $values): int
    {
        $gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        $chk = 1;
        foreach ($values as $v) {
            $b = $chk >> 25;
            $chk = (($chk & 0x1ffffff) << 5) ^ $v;
            for ($i = 0; $i < 5; $i++) {
                if (($b >> $i) & 1) {
                    $chk ^= $gen[$i];
                }
            }
        }
        return $chk;
    }

    private static function bechHrp(string $hrp): array
    {
        $o = [];
        for ($i = 0; $i < strlen($hrp); $i++) {
            $o[] = ord($hrp[$i]) >> 5;
        }
        $o[] = 0;
        for ($i = 0; $i < strlen($hrp); $i++) {
            $o[] = ord($hrp[$i]) & 31;
        }
        return $o;
    }

    /** @param int[] $data */
    public static function convertBits(array $data, int $from, int $to, bool $pad = true): array
    {
        $acc = 0;
        $bits = 0;
        $ret = [];
        $maxv = (1 << $to) - 1;
        foreach ($data as $v) {
            if ($v < 0 || ($v >> $from)) {
                throw new RareblException('invalid value in bit conversion');
            }
            $acc = (($acc << $from) | $v) & 0xFFFFFFFF;
            $bits += $from;
            while ($bits >= $to) {
                $bits -= $to;
                $ret[] = ($acc >> $bits) & $maxv;
            }
        }
        if ($pad) {
            if ($bits) {
                $ret[] = ($acc << ($to - $bits)) & $maxv;
            }
        } elseif ($bits >= $from || (($acc << ($to - $bits)) & $maxv)) {
            throw new RareblException('invalid padding');
        }
        return $ret;
    }

    private static function bytesToInts(string $b): array
    {
        return array_values(unpack('C*', $b) ?: []);
    }

    public static function segwitEncode(string $hrp, int $ver, string $prog): string
    {
        $const = $ver === 0 ? 1 : 0x2bc830a3;
        $data = array_merge([$ver], self::convertBits(self::bytesToInts($prog), 8, 5));
        $pm = self::bechPolymod(array_merge(self::bechHrp($hrp), $data, [0, 0, 0, 0, 0, 0])) ^ $const;
        $chk = [];
        for ($i = 0; $i < 6; $i++) {
            $chk[] = ($pm >> (5 * (5 - $i))) & 31;
        }
        $s = $hrp . '1';
        foreach (array_merge($data, $chk) as $d) {
            $s .= self::BECH[$d];
        }
        return $s;
    }

    /** @return array{0:int,1:string} */
    public static function segwitDecode(string $hrp, string $addr): array
    {
        if ($addr !== strtolower($addr) && $addr !== strtoupper($addr)) {
            throw new RareblException('mixed-case bech32');
        }
        $addr = strtolower($addr);
        $pos = strrpos($addr, '1');
        if ($pos === false || $pos < 1 || $pos + 7 > strlen($addr) || strlen($addr) > 90 || substr($addr, 0, $pos) !== $hrp) {
            throw new RareblException('bad bech32 hrp/length');
        }
        $data = [];
        for ($i = $pos + 1; $i < strlen($addr); $i++) {
            $p = strpos(self::BECH, $addr[$i]);
            if ($p === false) {
                throw new RareblException('invalid bech32 character');
            }
            $data[] = $p;
        }
        $ver = $data[0];
        if (self::bechPolymod(array_merge(self::bechHrp($hrp), $data)) !== ($ver === 0 ? 1 : 0x2bc830a3)) {
            throw new RareblException('bad bech32 checksum');
        }
        $prog = self::convertBits(array_slice($data, 1, -6), 5, 8, false);
        $p = $prog ? pack('C*', ...$prog) : '';
        if ($ver > 16 || strlen($p) < 2 || strlen($p) > 40 || ($ver === 0 && !in_array(strlen($p), [20, 32], true))) {
            throw new RareblException('bad witness program');
        }
        return [$ver, $p];
    }

    private static function cashPolymod(array $values): int
    {
        $gen = [0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470];
        $c = 1;
        foreach ($values as $d) {
            $c0 = $c >> 35;
            $c = (($c & 0x07ffffffff) << 5) ^ $d;
            for ($i = 0; $i < 5; $i++) {
                if (($c0 >> $i) & 1) {
                    $c ^= $gen[$i];
                }
            }
        }
        return $c ^ 1;
    }

    private static function prefixVals(string $prefix): array
    {
        $o = [];
        for ($i = 0; $i < strlen($prefix); $i++) {
            $o[] = ord($prefix[$i]) & 31;
        }
        $o[] = 0;
        return $o;
    }

    /** kind 0 = p2pkh, 1 = p2sh; 20-byte hash.  Returns the address without prefix. */
    public static function cashaddrEncode(string $prefix, int $kind, string $h): string
    {
        if (strlen($h) !== 20) {
            throw new RareblException('only 20-byte hashes are supported');
        }
        $payload = self::convertBits(self::bytesToInts(chr($kind << 3) . $h), 8, 5);
        $pm = self::cashPolymod(array_merge(self::prefixVals($prefix), $payload, array_fill(0, 8, 0)));
        $s = '';
        foreach ($payload as $d) {
            $s .= self::BECH[$d];
        }
        for ($i = 0; $i < 8; $i++) {
            $s .= self::BECH[($pm >> (5 * (7 - $i))) & 31];
        }
        return $s;
    }

    /** @return array{0:int,1:string} */
    public static function cashaddrDecode(string $addr, string $prefix = 'bitcoincash'): array
    {
        $a = trim($addr);
        if ($a !== strtolower($a) && $a !== strtoupper($a)) {
            throw new RareblException('mixed-case cashaddr');
        }
        $a = strtolower($a);
        if (str_contains($a, ':')) {
            [$pfx, $a] = explode(':', $a, 2);
            if ($pfx !== $prefix) {
                throw new RareblException('wrong cashaddr prefix');
            }
        }
        $data = [];
        for ($i = 0; $i < strlen($a); $i++) {
            $p = strpos(self::BECH, $a[$i]);
            if ($p === false) {
                throw new RareblException('invalid cashaddr character');
            }
            $data[] = $p;
        }
        if (count($data) < 9 || self::cashPolymod(array_merge(self::prefixVals($prefix), $data)) !== 0) {
            throw new RareblException('bad cashaddr checksum');
        }
        $raw = self::convertBits(array_slice($data, 0, -8), 5, 8, false);
        $ver = $raw[0];
        $h = pack('C*', ...array_slice($raw, 1));
        if (($ver & 0x80) || ($ver & 7) || strlen($h) !== 20 || !in_array($ver >> 3, [0, 1], true)) {
            throw new RareblException('unsupported cashaddr version');
        }
        return [$ver >> 3, $h];
    }
}

// ---------------------------------------------------------------------------------------
// chains, addresses, keys

final class Chains
{
    public const TABLE = [
        'btc' => ['p2pkh' => 0x00, 'p2sh' => 0x05, 'hrp' => 'bc', 'wif' => 0x80, 'utxo' => true],
        'ltc' => ['p2pkh' => 0x30, 'p2sh' => 0x32, 'hrp' => 'ltc', 'wif' => 0xB0, 'utxo' => true],
        'bch' => ['p2pkh' => 0x00, 'p2sh' => 0x05, 'cash' => 'bitcoincash', 'wif' => 0x80, 'utxo' => true],
        'dash' => ['p2pkh' => 0x4C, 'p2sh' => 0x10, 'wif' => 0xCC, 'utxo' => true],
        'eth' => ['utxo' => false],
        'tron' => ['utxo' => false],
    ];
    public const TYPES = [
        'btc' => ['p2wpkh', 'p2pkh', 'p2sh-p2wpkh', 'p2tr'],
        'ltc' => ['p2wpkh', 'p2pkh', 'p2sh-p2wpkh', 'p2tr'],
        'bch' => ['p2pkh'],
        'dash' => ['p2pkh'],
        'eth' => ['eoa', 'eth'],
        'tron' => ['eoa', 'tron'],
    ];

    public static function chain(string $chain): string
    {
        $c = strtolower($chain);
        if (!isset(self::TABLE[$c])) {
            throw new RareblException("unknown chain '$chain' (btc, ltc, bch, dash, eth, tron)");
        }
        return $c;
    }

    public static function type(string $chain, ?string $type): string
    {
        $type ??= self::TYPES[$chain][0];
        if (!in_array($type, self::TYPES[$chain], true)) {
            throw new RareblException("address type '$type' is not supported on $chain (" . implode(', ', self::TYPES[$chain]) . ')');
        }
        return $type;
    }

    public static function isUtxo(string $chain): bool
    {
        return self::TABLE[$chain]['utxo'];
    }
}

final class Address
{
    public static function eip55(string $a20): string
    {
        $h = bin2hex($a20);
        $dig = bin2hex(Hash::keccak256($h));
        $o = '';
        for ($i = 0; $i < 40; $i++) {
            $o .= (ctype_alpha($h[$i]) && hexdec($dig[$i]) >= 8) ? strtoupper($h[$i]) : $h[$i];
        }
        return '0x' . $o;
    }

    /** Address from a public key (33-byte compressed, or 32-byte x-only for p2tr), as bytes or hex. */
    public static function derive(string $chain, string $publicKey, ?string $type = null): string
    {
        Secp::init();
        $chain = Chains::chain($chain);
        $type = Chains::type($chain, $type);
        return self::deriveBin($chain, $type, U::unhex($publicKey, 'publicKey'));
    }

    public static function deriveBin(string $chain, string $type, string $pub): string
    {
        Secp::init();
        if ($chain === 'eth' || $chain === 'tron') {
            $pt = Secp::parsePub($pub);
            $a20 = substr(Hash::keccak256(substr(Secp::serUncompressed($pt), 1)), -20);
            return $chain === 'eth' ? self::eip55($a20) : Codec::b58checkEncode("\x41" . $a20);
        }
        $c = Chains::TABLE[$chain];
        if ($type === 'p2tr') {
            $internal = strlen($pub) === 32 ? $pub : substr(Secp::serCompressed(Secp::parsePub($pub)), 1);
            return Codec::segwitEncode($c['hrp'], 1, Secp::taprootTweakPub($internal));
        }
        $pub33 = strlen($pub) !== 33 ? Secp::serCompressed(Secp::parsePub($pub)) : $pub;
        $h = Hash::hash160($pub33);
        return match ($type) {
            'p2pkh' => $chain === 'bch' ? Codec::cashaddrEncode($c['cash'], 0, $h) : Codec::b58checkEncode(chr($c['p2pkh']) . $h),
            'p2wpkh' => Codec::segwitEncode($c['hrp'], 0, $h),
            'p2sh-p2wpkh' => Codec::b58checkEncode(chr($c['p2sh']) . Hash::hash160("\x00\x14" . $h)),
            default => throw new RareblException('unsupported address type'),
        };
    }

    /** @return array{0:string,1:string,2:string} [scriptPubKey|raw, type, normalized] */
    public static function script(string $chain, string $addr): array
    {
        Secp::init();
        $chain = Chains::chain($chain);
        if ($addr === '') {
            throw new RareblException('empty address');
        }
        if ($chain === 'eth') {
            if (!(strlen($addr) === 42 && str_starts_with($addr, '0x') && ctype_xdigit(substr($addr, 2)))) {
                throw new RareblException('bad eth address');
            }
            $raw = (string)hex2bin(substr($addr, 2));
            $norm = self::eip55($raw);
            $body = substr($addr, 2);
            if ($body !== strtolower($body) && $body !== strtoupper($body) && $addr !== $norm) {
                throw new RareblException('bad EIP-55 checksum');
            }
            return [$raw, 'eth', $norm];
        }
        if ($chain === 'tron') {
            $raw = Codec::b58checkDecode($addr);
            if (strlen($raw) !== 21 || $raw[0] !== "\x41") {
                throw new RareblException('bad tron address');
            }
            return [$raw, 'tron', $addr];
        }
        $c = Chains::TABLE[$chain];
        if ($chain === 'bch') {
            try {
                [$kind, $h] = Codec::cashaddrDecode($addr, $c['cash']);
                $norm = Codec::cashaddrEncode($c['cash'], $kind, $h);
                $scr = $kind === 0 ? "\x76\xa9\x14" . $h . "\x88\xac" : "\xa9\x14" . $h . "\x87";
                return [$scr, $kind === 0 ? 'p2pkh' : 'p2sh', $norm];
            } catch (RareblException) {
                // maybe legacy
            }
        }
        if (isset($c['hrp']) && str_starts_with(strtolower($addr), $c['hrp'] . '1')) {
            [$ver, $prog] = Codec::segwitDecode($c['hrp'], $addr);
            $a = strtolower($addr);
            if ($ver === 0 && strlen($prog) === 20) {
                return ["\x00\x14" . $prog, 'p2wpkh', $a];
            }
            if ($ver === 0 && strlen($prog) === 32) {
                return ["\x00\x20" . $prog, 'p2wsh', $a];
            }
            if ($ver === 1 && strlen($prog) === 32) {
                return ["\x51\x20" . $prog, 'p2tr', $a];
            }
            throw new RareblException('unsupported witness program');
        }
        $raw = Codec::b58checkDecode($addr);
        if (strlen($raw) !== 21) {
            throw new RareblException('bad base58 address length');
        }
        $ver = ord($raw[0]);
        if ($ver === $c['p2pkh']) {
            $scr = "\x76\xa9\x14" . substr($raw, 1) . "\x88\xac";
            $typ = 'p2pkh';
        } elseif ($ver === $c['p2sh']) {
            $scr = "\xa9\x14" . substr($raw, 1) . "\x87";
            $typ = 'p2sh';
        } else {
            throw new RareblException("address version byte does not belong to $chain");
        }
        $norm = $addr;
        if ($chain === 'bch') {
            $norm = Codec::cashaddrEncode($c['cash'], $typ === 'p2pkh' ? 0 : 1, substr($raw, 1));
        }
        return [$scr, $typ, $norm];
    }

    /** @return array{valid:bool,type:?string,normalized:?string} */
    public static function validate(string $chain, string $addr): array
    {
        try {
            [, $typ, $norm] = self::script($chain, $addr);
            return ['valid' => true, 'type' => $typ, 'normalized' => $norm];
        } catch (RareblException) {
            return ['valid' => false, 'type' => null, 'normalized' => null];
        }
    }

    public static function same(string $chain, string $a, string $b): bool
    {
        try {
            return self::script($chain, $a)[0] === self::script($chain, $b)[0];
        } catch (RareblException) {
            return false;
        }
    }
}

final class Keys
{
    /** Accepts 64-hex (optional 0x) or WIF.  Returns the secret as GMP. */
    public static function parse(?string $chain, string|GMP $key): GMP
    {
        Secp::init();
        if ($key instanceof GMP) {
            return Secp::checkScalar($key);
        }
        $k = trim($key);
        $h = (str_starts_with($k, '0x') || str_starts_with($k, '0X')) ? substr($k, 2) : $k;
        if (strlen($h) === 64 && ctype_xdigit($h)) {
            return Secp::checkScalar(U::g($h));
        }
        try {
            $raw = Codec::b58checkDecode($k);
        } catch (RareblException) {
            throw new RareblException('unrecognised private key (expected 64 hex chars or WIF)');
        }
        if (strlen($raw) === 34 && $raw[33] === "\x01") {
            $raw = substr($raw, 0, 33);
        }
        if (strlen($raw) !== 33) {
            throw new RareblException('bad WIF length');
        }
        if ($chain !== null && isset(Chains::TABLE[$chain]['wif']) && ord($raw[0]) !== Chains::TABLE[$chain]['wif']) {
            throw new RareblException("WIF version byte does not match $chain");
        }
        return Secp::checkScalar(U::bytesToG(substr($raw, 1)));
    }

    public static function wif(string $chain, GMP $d): string
    {
        return Codec::b58checkEncode(chr(Chains::TABLE[$chain]['wif']) . U::gToBytes($d) . "\x01");
    }

    /** @return array<string,string> */
    public static function fromPrivate(string $chain, string|GMP $key, ?string $type = null): array
    {
        $chain = Chains::chain($chain);
        $type = Chains::type($chain, $type);
        $d = self::parse($chain, $key);
        $pub = Secp::pubkeyCreate($d);
        $out = ['privateKey' => bin2hex(U::gToBytes($d)), 'publicKey' => bin2hex($pub),
            'address' => Address::deriveBin($chain, $type, $pub), 'type' => $type];
        if (Chains::isUtxo($chain)) {
            $out['wif'] = self::wif($chain, $d);
        }
        if ($type === 'p2tr') {
            $out['outputKey'] = bin2hex(Secp::taprootTweakPub(substr($pub, 1)));
        }
        return $out;
    }

    /** New keypair from the OS CSPRNG.  Nothing is sent anywhere. */
    public static function generate(string $chain, ?string $type = null): array
    {
        Secp::init();
        do {
            $d = U::bytesToG(random_bytes(32));
        } while (gmp_cmp($d, 1) < 0 || gmp_cmp($d, Secp::$N) >= 0);
        return self::fromPrivate($chain, bin2hex(U::gToBytes($d)), $type);
    }
}

// ---------------------------------------------------------------------------------------
// Bitcoin-family transaction helpers, RLP, protobuf

final class Tx
{
    /** @return array{version:int,inputs:array,outputs:array,locktime:int,witnesses:array} */
    public static function parse(string $b): array
    {
        $i = 0;
        $take = function (int $n) use (&$i, $b): string {
            if ($i + $n > strlen($b)) {
                throw new VerifyException('truncated transaction');
            }
            $v = substr($b, $i, $n);
            $i += $n;
            return $v;
        };
        $varint = function () use (&$take): int {
            $f = ord($take(1));
            if ($f < 0xFD) {
                return $f;
            }
            $n = [0xFD => 2, 0xFE => 4, 0xFF => 8][$f];
            return (int)unpack($n === 2 ? 'v' : ($n === 4 ? 'V' : 'P'), $take($n))[1];
        };
        $version = unpack('V', $take(4))[1];
        $segwit = false;
        if (substr($b, 4, 2) === "\x00\x01") {
            $segwit = true;
            $take(2);
        }
        $ins = [];
        for ($n = $varint(); $n > 0; $n--) {
            $txid = bin2hex(strrev($take(32)));
            $vout = unpack('V', $take(4))[1];
            $script = $take($varint());
            $seq = unpack('V', $take(4))[1];
            $ins[] = ['txid' => $txid, 'vout' => $vout, 'script' => $script, 'sequence' => $seq];
        }
        $outs = [];
        for ($n = $varint(); $n > 0; $n--) {
            $val = unpack('P', $take(8))[1];
            if ($val < 0) {
                throw new VerifyException('output value out of range');
            }
            $outs[] = ['value' => $val, 'script' => $take($varint())];
        }
        $wit = [];
        if ($segwit) {
            foreach ($ins as $_) {
                $items = [];
                for ($n = $varint(); $n > 0; $n--) {
                    $items[] = $take($varint());
                }
                $wit[] = $items;
            }
        }
        $locktime = unpack('V', $take(4))[1];
        if ($i !== strlen($b)) {
            throw new VerifyException('trailing bytes in transaction');
        }
        return ['version' => $version, 'inputs' => $ins, 'outputs' => $outs, 'locktime' => $locktime, 'witnesses' => $wit];
    }

    /**
     * Parse a previous (signed) transaction.  Returns [txid (display order, double SHA-256 of the serialisation
     * WITHOUT witness data), outputs [['value' => int, 'script' => bytes], ...]].
     */
    public static function parsePrev(string $b): array
    {
        $i = 0;
        $take = function (int $n) use (&$i, $b): string {
            if ($n < 0 || $i + $n > strlen($b)) {
                throw new VerifyException('truncated transaction');
            }
            $v = substr($b, $i, $n);
            $i += $n;
            return $v;
        };
        $varint = function () use (&$take): int {
            $f = ord($take(1));
            if ($f < 0xFD) {
                return $f;
            }
            $n = [0xFD => 2, 0xFE => 4, 0xFF => 8][$f];
            return (int)unpack($n === 2 ? 'v' : ($n === 4 ? 'V' : 'P'), $take($n))[1];
        };
        $ser = $take(4);
        $segwit = substr($b, 4, 2) === "\x00\x01";
        if ($segwit) {
            $take(2);
        }
        $nIn = $varint();
        $ser .= U::varint($nIn);
        for ($n = 0; $n < $nIn; $n++) {
            $ser .= $take(36);
            $script = $take($varint());
            $ser .= U::varint(strlen($script)) . $script . $take(4);
        }
        $nOut = $varint();
        $ser .= U::varint($nOut);
        $outs = [];
        for ($n = 0; $n < $nOut; $n++) {
            $val = $take(8);
            $script = $take($varint());
            $v = unpack('P', $val)[1];
            if ($v < 0) {
                throw new VerifyException('output value out of range');
            }
            $outs[] = ['value' => $v, 'script' => $script];
            $ser .= $val . U::varint(strlen($script)) . $script;
        }
        if ($segwit) {
            for ($n = 0; $n < $nIn; $n++) {
                for ($m = $varint(); $m > 0; $m--) {
                    $take($varint());
                }
            }
        }
        $ser .= $take(4);
        if ($i !== strlen($b)) {
            throw new VerifyException('trailing bytes in prevTx');
        }
        return [bin2hex(strrev(Hash::dsha256($ser))), $outs];
    }

    private static function outpoint(array $i): string
    {
        return strrev((string)hex2bin($i['txid'])) . pack('V', $i['vout']);
    }

    private static function serOut(array $o): string
    {
        return pack('P', $o['value']) . U::varint(strlen($o['script'])) . $o['script'];
    }

    public static function sighashLegacy(array $tx, int $idx, string $scriptCode, int $hashtype = 1): string
    {
        if ($hashtype !== 1) {
            throw new VerifyException('only SIGHASH_ALL is supported for legacy digests');
        }
        $out = pack('V', $tx['version']) . U::varint(count($tx['inputs']));
        foreach ($tx['inputs'] as $n => $i) {
            $sc = $n === $idx ? $scriptCode : '';
            $out .= self::outpoint($i) . U::varint(strlen($sc)) . $sc . pack('V', $i['sequence']);
        }
        $out .= U::varint(count($tx['outputs'])) . implode('', array_map([self::class, 'serOut'], $tx['outputs']));
        $out .= pack('VV', $tx['locktime'], $hashtype);
        return Hash::dsha256($out);
    }

    /** BIP143 digest (also BCH FORKID when hashtype = 0x41, fork id 0). */
    public static function sighashBip143(array $tx, int $idx, string $scriptCode, int $amount, int $hashtype = 1): string
    {
        if (!in_array($hashtype, [1, 0x41], true)) {
            throw new VerifyException('only SIGHASH_ALL (1) / ALL|FORKID (0x41) are supported');
        }
        $hp = Hash::dsha256(implode('', array_map([self::class, 'outpoint'], $tx['inputs'])));
        $hs = Hash::dsha256(implode('', array_map(fn($i) => pack('V', $i['sequence']), $tx['inputs'])));
        $ho = Hash::dsha256(implode('', array_map([self::class, 'serOut'], $tx['outputs'])));
        $i = $tx['inputs'][$idx];
        $pre = pack('V', $tx['version']) . $hp . $hs . self::outpoint($i) . U::varint(strlen($scriptCode)) . $scriptCode
            . pack('P', $amount) . pack('V', $i['sequence']) . $ho . pack('VV', $tx['locktime'], $hashtype);
        return Hash::dsha256($pre);
    }

    /** BIP341 key-path digest, SIGHASH_DEFAULT.  $prevouts = [[amount, scriptPubKey], ...] */
    public static function sighashBip341Default(array $tx, int $idx, array $prevouts, int $hashtype = 0): string
    {
        if ($hashtype !== 0 && $hashtype !== 1) {
            throw new VerifyException('only SIGHASH_DEFAULT (0) and SIGHASH_ALL (1) are supported for taproot');
        }
        $sp = Hash::sha256(implode('', array_map([self::class, 'outpoint'], $tx['inputs'])));
        $sa = Hash::sha256(implode('', array_map(fn($p) => pack('P', $p[0]), $prevouts)));
        $ss = Hash::sha256(implode('', array_map(fn($p) => U::varint(strlen($p[1])) . $p[1], $prevouts)));
        $sq = Hash::sha256(implode('', array_map(fn($i) => pack('V', $i['sequence']), $tx['inputs'])));
        $so = Hash::sha256(implode('', array_map([self::class, 'serOut'], $tx['outputs'])));
        $msg = chr($hashtype) . pack('V', $tx['version']) . pack('V', $tx['locktime']) . $sp . $sa . $ss . $sq . $so . "\x00" . pack('V', $idx);
        return Hash::tagged('TapSighash', "\x00" . $msg);
    }

    /** RLP encoding of strings (bytes), GMP/int (big-endian, minimal), and lists (arrays). */
    public static function rlp(mixed $x): string
    {
        if (is_string($x)) {
            if (strlen($x) === 1 && ord($x[0]) < 0x80) {
                return $x;
            }
            return self::rlpLen(strlen($x), 0x80) . $x;
        }
        if ($x instanceof GMP || is_int($x)) {
            return self::rlp(U::gMin($x instanceof GMP ? $x : gmp_init($x)));
        }
        $body = '';
        foreach ($x as $i) {
            $body .= self::rlp($i);
        }
        return self::rlpLen(strlen($body), 0xC0) . $body;
    }

    private static function rlpLen(int $n, int $off): string
    {
        if ($n < 56) {
            return chr($off + $n);
        }
        $b = ltrim(pack('J', $n), "\x00");
        return chr($off + 55 + strlen($b)) . $b;
    }

    public static function pbVarint(string $b, int &$i): int
    {
        $v = 0;
        $s = 0;
        while (true) {
            if ($i >= strlen($b)) {
                throw new VerifyException('truncated protobuf varint');
            }
            $c = ord($b[$i++]);
            $v |= ($c & 0x7F) << $s;
            $s += 7;
            if (!($c & 0x80)) {
                return $v;
            }
            if ($s > 63) {
                throw new VerifyException('protobuf varint too long');
            }
        }
    }

    /** Minimal protobuf reader: field => [values] (varint -> int, length-delimited -> string). */
    public static function pbParse(string $b): array
    {
        $out = [];
        $i = 0;
        while ($i < strlen($b)) {
            $key = self::pbVarint($b, $i);
            $f = $key >> 3;
            $wt = $key & 7;
            if ($wt === 0) {
                $v = self::pbVarint($b, $i);
            } elseif ($wt === 2) {
                $n = self::pbVarint($b, $i);
                if ($i + $n > strlen($b)) {
                    throw new VerifyException('truncated protobuf');
                }
                $v = substr($b, $i, $n);
                $i += $n;
            } elseif ($wt === 1) {
                $v = substr($b, $i, 8);
                $i += 8;
            } elseif ($wt === 5) {
                $v = substr($b, $i, 4);
                $i += 4;
            } else {
                throw new VerifyException('unsupported protobuf wire type');
            }
            $out[$f][] = $v;
        }
        return $out;
    }
}

// ---------------------------------------------------------------------------------------
// Signer: signDigest, verifyBuild, signBuild

final class Signer
{
    public const ALGOS = ['ecdsa-secp256k1', 'schnorr-bip340', 'ecdsa-secp256k1-recoverable'];

    /**
     * Sign a 32-byte digest (hex).  ecdsa-secp256k1 -> DER + sighash byte (default 1);
     * schnorr-bip340 -> 64 bytes (+ type byte if != 0; the key is used as given, no taproot
     * tweak: signBuild applies the tweak); ecdsa-secp256k1-recoverable -> r||s||v (65 bytes, v = 0/1).
     * Returns lowercase hex.  Schnorr uses random BIP340 aux randomness unless $deterministic (zero aux, reproducible).
     */
    public static function signDigest(string $digestHex, string $privateKey, string $algorithm, ?int $sighashType = null, ?string $chain = null, bool $deterministic = false): string
    {
        Secp::init();
        $h = U::unhex($digestHex, 'digest');
        if (strlen($h) !== 32) {
            throw new RareblException('digest must be 32 bytes');
        }
        $d = Keys::parse($chain, $privateKey);
        return bin2hex(self::signRaw($h, $d, $algorithm, $sighashType, $deterministic));
    }

    public static function signRaw(string $h, GMP $d, string $algorithm, ?int $sighashType = null, bool $deterministic = false): string
    {
        if ($algorithm === 'ecdsa-secp256k1') {
            [$r, $s] = Secp::ecdsaSign($h, $d);
            if (!Secp::ecdsaVerify($h, $r, $s, Secp::pubPoint($d))) {
                throw new RareblException('verify-after-sign failed');
            }
            return Secp::derEncode($r, $s) . chr($sighashType ?? 1);
        }
        if ($algorithm === 'schnorr-bip340') {
            return Secp::schnorrSign($h, $d, $deterministic ? str_repeat("\x00", 32) : null) . ($sighashType ? chr($sighashType) : '');
        }
        if ($algorithm === 'ecdsa-secp256k1-recoverable') {
            [$r, $s, $v] = Secp::ecdsaSign($h, $d);
            $q = Secp::ecdsaRecover($h, $r, $s, $v);
            $pub = Secp::pubPoint($d);
            if (gmp_cmp($q[0], $pub[0]) !== 0 || gmp_cmp($q[1], $pub[1]) !== 0) {
                throw new RareblException('verify-after-sign failed');
            }
            return U::gToBytes($r) . U::gToBytes($s) . chr($v);
        }
        throw new RareblException("unknown algorithm '$algorithm'");
    }

    // --- verifyBuild ---------------------------------------------------------------------

    private static function spkMatches(string $spk, ?string $typ): bool
    {
        return match ($typ) {
            'p2pkh' => strlen($spk) === 25 && str_starts_with($spk, "\x76\xa9\x14") && substr($spk, 23) === "\x88\xac",
            'p2wpkh' => strlen($spk) === 22 && str_starts_with($spk, "\x00\x14"),
            'p2sh-p2wpkh' => strlen($spk) === 23 && str_starts_with($spk, "\xa9\x14") && $spk[22] === "\x87",
            'p2tr' => strlen($spk) === 34 && str_starts_with($spk, "\x51\x20"),
            default => false,
        };
    }

    private static function p2pkhScript(string $h): string
    {
        return "\x76\xa9\x14" . $h . "\x88\xac";
    }

    private static function scriptCode(array $inp, string $typ, ?string $pubkey): string
    {
        $spk = U::unhex($inp['scriptPubKey'], 'scriptPubKey');
        if ($typ === 'p2pkh') {
            return $spk;
        }
        if ($typ === 'p2wpkh') {
            return self::p2pkhScript(substr($spk, 2, 20));
        }
        if ($typ === 'p2sh-p2wpkh') {
            if ($pubkey === null) {
                throw new VerifyException('p2sh-p2wpkh needs the public key to rebuild the script code (pass pubkeys)');
            }
            $h = Hash::hash160($pubkey);
            if (Hash::hash160("\x00\x14" . $h) !== substr($spk, 2, 20)) {
                throw new KeyMismatchException('public key does not match the p2sh-p2wpkh input');
            }
            return self::p2pkhScript($h);
        }
        throw new VerifyException("unsupported scriptType '$typ'");
    }

    /**
     * Recompute every digest in a tx/build reply from its `unsigned` data and check the
     * outputs.  Returns true or throws VerifyException.  $pubkeys = [index => pubkey bytes]
     * (needed only for p2sh-p2wpkh).  $expect (optional) pins what you asked for:
     *   UTXO: ['to'=>[['address','amount']], 'allowed'=>[change addrs], 'maxFeeSats'=>n]
     *   ETH:  ['to','amountUnits','token','from','maxFeeWei']
     *   TRON: ['to','amountUnits','token','from','feeLimit']
     */
    /**
     * Recompute every digest of a tx/build reply and check what is being signed.  Throws VerifyException.
     * $expect pins the payment (see normExpect); UTXO also "maxFeeRate" (sat/vB; default 1000 btc/ltc, 50 bch/dash)
     * and "allowLocktime"; ETH "maxFeePerGas" / "maxPriorityFeePerGas" (wei; defaults 500 gwei and
     * max(5 gwei, maxFeePerGas/2)) and a default total cap of 0.05 ETH; TRON "maxFeeLimit" (default 150 TRX).
     * $prevTxs is [txid => raw previous tx hex] for legacy p2pkh inputs when the reply has no inputs[i].prevTx.
     */
    public static function verifyBuild(array $build, ?array $pubkeys = null, ?array $expect = null, ?int $nowMs = null, ?array $prevTxs = null): bool
    {
        Secp::init();
        set_error_handler(static function (int $no, string $str): bool {
            throw new \ErrorException($str, 0, $no);
        });
        try {
            $u = $build['unsigned'];
            $toSign = $build['toSign'];
            $chain = Chains::chain($u['chain']);
            $expect = self::normExpect($chain, $expect);
            $fmt = $u['format'] ?? null;
            if ($fmt === 'utxo-v1' && Chains::isUtxo($chain)) {
                return self::verifyUtxo($chain, $u, $toSign, $pubkeys, $expect, $prevTxs);
            }
            if ($fmt === 'eth-1559-v1' && $chain === 'eth') {
                return self::verifyEth($u, $toSign, $expect);
            }
            if ($fmt === 'tron-v1' && $chain === 'tron') {
                return self::verifyTron($u, $toSign, $expect, $nowMs);
            }
            throw new VerifyException("unknown format '" . json_encode($fmt) . "' for chain $chain");
        } catch (VerifyException | KeyMismatchException $e) {
            throw $e;
        } catch (RareblException | \Error | \ErrorException $e) {
            throw new VerifyException('malformed build reply: ' . $e->getMessage());
        } finally {
            restore_error_handler();
        }
    }

    public const DEFAULT_MAX_FEE_RATE = ['btc' => 1000, 'ltc' => 1000, 'bch' => 50, 'dash' => 50];  // sat/vB (sat/byte on bch, dash)

    /** Rough virtual size of the signed tx (same table as the JS SDK), used for the fee-rate cap. */
    private static function estimateVsize(array $tx, array $spks): int
    {
        $sig = ['p2pkh' => [107, 0], 'p2sh-p2wpkh' => [23, 108], 'p2wpkh' => [0, 108], 'p2tr' => [0, 66]];
        $base = 10 + 41 * count($tx['inputs']);
        foreach ($tx['outputs'] as $o) {
            $base += 9 + strlen($o['script']);
        }
        $w = 0;
        $hasW = false;
        foreach ($spks as $spk) {
            $typ = 'p2pkh';
            foreach (array_keys($sig) as $t) {
                if (self::spkMatches($spk, $t)) {
                    $typ = $t;
                    break;
                }
            }
            [$sc, $wit] = $sig[$typ];
            $w += $sc * 4;
            if ($wit) {
                $hasW = true;
                $w += $wit;
            }
        }
        return (int)ceil(($base * 4 + $w + ($hasW ? 2 : 0)) / 4);
    }

    private static function verifyUtxo(string $chain, array $u, array $toSign, ?array $pubkeys, ?array $expect, ?array $prevTxs = null): bool
    {
        $expect ??= [];
        $tx = Tx::parse(U::unhex($u['tx'], 'tx'));
        if ($tx['version'] !== 1 && $tx['version'] !== 2) {
            throw new VerifyException("unsigned.tx has version {$tx['version']}; only 1 and 2 are accepted");
        }
        if ($tx['locktime'] !== 0 && ($expect['allowLocktime'] ?? false) !== true) {
            throw new VerifyException("unsigned.tx has locktime {$tx['locktime']}; a non-zero locktime is refused unless expect['allowLocktime'] is true");
        }
        $seen = [];
        foreach ($tx['inputs'] as $ti) {
            $seen[$ti['txid'] . ':' . $ti['vout']] = true;
        }
        if (count($seen) !== count($tx['inputs'])) {
            throw new VerifyException('unsigned.tx spends the same outpoint twice');
        }
        $uin = $u['inputs'] ?? [];
        $uout = array_values(array_filter($u['outputs'] ?? [], fn($o) => !empty($o['address'])));  // entries without an address would be OP_RETURN
        $nonret = array_values(array_filter($tx['outputs'], fn($o) => ($o['script'][0] ?? '') !== "\x6a"));
        if (count($tx['inputs']) !== count($uin) || !$uin) {
            throw new VerifyException('input count does not match the transaction');
        }
        if (count($nonret) !== count($uout) || !$uout) {
            throw new VerifyException('output count does not match the transaction');
        }
        foreach ($tx['inputs'] as $k => $ti) {
            $ui = $uin[$k];
            if ($ti['script'] !== '') {
                throw new VerifyException("input $k already has a scriptSig");
            }
            if ($ti['txid'] !== strtolower((string)$ui['txid']) || $ti['vout'] !== (int)$ui['vout']) {
                throw new VerifyException("input $k outpoint does not match the transaction");
            }
            if (isset($ui['sequence']) && (int)$ui['sequence'] !== $ti['sequence']) {
                throw new VerifyException("input $k sequence does not match the transaction");
            }
        }
        foreach ($tx['witnesses'] as $w) {
            if ($w) {
                throw new VerifyException('transaction already carries witness data');
            }
        }
        $amounts = [];
        $spks = [];
        $typs = [];
        foreach ($uin as $k => $ui) {
            $spk = U::unhex($ui['scriptPubKey'], 'scriptPubKey');
            if ($spk !== Address::script($chain, $ui['address'])[0]) {
                throw new VerifyException("input $k scriptPubKey does not match its address");
            }
            $typ = $ui['scriptType'] ?? null;
            if ($typ && !self::spkMatches($spk, $typ)) {
                throw new VerifyException("input $k scriptType $typ does not match its scriptPubKey");
            }
            $value = U::num($ui['valueSats'], 'valueSats');
            // legacy p2pkh (btc, ltc, dash) signs a digest that does not commit to the amount: prove it with the previous tx
            $proofs = array_values(array_filter([$ui['prevTx'] ?? null, $prevTxs[$tx['inputs'][$k]['txid']] ?? null], fn($p) => $p !== null && $p !== ''));
            if (!$proofs && $chain !== 'bch' && self::spkMatches($spk, 'p2pkh')) {
                throw new VerifyException("input $k: legacy p2pkh does not commit to its amount, so unsigned.inputs[$k].prevTx (or prevTxs) is required");
            }
            foreach ($proofs as $raw) {
                [$ptxid, $pouts] = Tx::parsePrev(U::unhex($raw, 'prevTx'));
                if ($ptxid !== $tx['inputs'][$k]['txid']) {
                    throw new VerifyException("input $k: prevTx does not hash to the txid it is meant to prove");
                }
                $vo = $tx['inputs'][$k]['vout'];
                if (!isset($pouts[$vo])) {
                    throw new VerifyException("input $k: prevTx has no output $vo");
                }
                if ($pouts[$vo]['script'] !== $spk) {
                    throw new VerifyException("input $k: prevTx output script differs from scriptPubKey");
                }
                if (gmp_cmp(gmp_init($pouts[$vo]['value']), $value) !== 0) {
                    throw new VerifyException("input $k: valueSats (" . gmp_strval($value) . ") differs from the previous transaction ({$pouts[$vo]['value']})");
                }
            }
            $amounts[$k] = $value;
            $spks[$k] = $spk;
            $typs[$k] = $typ;
        }
        $outSum = gmp_init(0);
        $outInfo = [];
        $opReturns = [];
        $j = 0;
        foreach ($tx['outputs'] as $k => $to) {
            if ($to['script'] !== '' && $to['script'][0] === "\x6a") {
                if ($to['value'] !== 0) {
                    throw new VerifyException("OP_RETURN output $k carries value");
                }
                $opReturns[] = self::opReturnData($to['script']);
                continue;
            }
            $uo = $uout[$j++];
            if ($to['script'] !== Address::script($chain, $uo['address'])[0]) {
                throw new VerifyException("output $k script does not match its address");
            }
            if (gmp_cmp(gmp_init($to['value']), U::num($uo['valueSats'], 'valueSats')) !== 0) {
                throw new VerifyException("output $k value does not match the transaction");
            }
            $outSum += $to['value'];
            $outInfo[] = [$uo['address'], gmp_init($to['value'])];
        }
        $inSum = gmp_init(0);
        foreach ($amounts as $a) {
            $inSum += $a;
        }
        $fee = $inSum - $outSum;
        if (gmp_sign($fee) < 0) {
            throw new VerifyException('outputs exceed inputs');
        }
        if (isset($u['feeSats']) && gmp_cmp(U::num($u['feeSats'], 'feeSats'), $fee) !== 0) {
            throw new VerifyException("reported fee {$u['feeSats']} does not match inputs - outputs (" . gmp_strval($fee) . ')');
        }
        $est = self::estimateVsize($tx, $spks);
        if (isset($expect['maxFeeSats']) && gmp_cmp($fee, gmp_init((string)$expect['maxFeeSats'])) > 0) {
            throw new VerifyException('fee ' . gmp_strval($fee) . ' exceeds the cap ' . $expect['maxFeeSats']);
        }
        if (isset($expect['maxFeeRate']) || !isset($expect['maxFeeSats'])) {
            $rate = isset($expect['maxFeeRate']) ? (float)$expect['maxFeeRate'] : (float)self::DEFAULT_MAX_FEE_RATE[$chain];
            if (!($rate > 0)) {
                throw new VerifyException("expect['maxFeeRate'] must be positive");
            }
            if (gmp_cmp($fee * 4, gmp_init((string)(int)ceil($rate * 1.25 * $est * 4))) > 0) {
                throw new VerifyException('fee ' . gmp_strval($fee) . " sats is above $rate sat/vB for about $est vB; pass maxFeeRate (or maxFee) to allow it");
            }
        }
        if (isset($expect['to'])) {
            self::checkUtxoExpect($chain, $outInfo, $expect, $spks);
            $wantRet = !empty($expect['opReturn']) ? [U::unhex($expect['opReturn'])] : [];
            if ($opReturns !== $wantRet) {
                throw new VerifyException("the transaction's OP_RETURN data does not match the request");
            }
        }
        if (!$toSign) {
            throw new VerifyException('nothing to sign');
        }
        foreach ($toSign as $ts) {
            $idx = (int)$ts['index'];
            if ($idx < 0 || $idx >= count($uin)) {
                throw new VerifyException("toSign index $idx out of range");
            }
            if (!empty($ts['address']) && Address::script($chain, $ts['address'])[0] !== $spks[$idx]) {
                throw new VerifyException("toSign $idx address does not match input $idx");
            }
            $typ = $ts['scriptType'] ?? $typs[$idx];
            if ($typ === null) {
                throw new VerifyException("toSign $idx has no scriptType");
            }
            if ($typs[$idx] !== null && $typ !== $typs[$idx]) {
                throw new VerifyException("toSign $idx scriptType disagrees with the input");
            }
            $algo = $ts['algorithm'] ?? null;
            $sht = $ts['sighashType'] ?? null;
            $sht = $sht === null ? ($typ === 'p2tr' ? 0 : 1) : (int)$sht;
            $amt = gmp_intval($amounts[$idx]);
            $pk = $pubkeys[$idx] ?? null;
            if ($typ === 'p2tr') {
                if ($algo !== 'schnorr-bip340' || ($sht !== 0 && $sht !== 1)) {
                    throw new VerifyException('p2tr must use schnorr-bip340 with SIGHASH_DEFAULT or ALL');
                }
                $prev = [];
                foreach ($amounts as $k => $a) {
                    $prev[] = [gmp_intval($a), $spks[$k]];
                }
                $digest = Tx::sighashBip341Default($tx, $idx, $prev, $sht);
            } else {
                if ($algo !== 'ecdsa-secp256k1') {
                    throw new VerifyException("unexpected algorithm '" . json_encode($algo) . "' for $typ");
                }
                if ($chain === 'bch') {
                    if ($sht !== 0x41) {
                        throw new VerifyException('BCH requires sighashType 0x41');
                    }
                    $digest = Tx::sighashBip143($tx, $idx, self::scriptCode($uin[$idx], $typ, $pk), $amt, 0x41);
                } elseif ($typ === 'p2pkh') {
                    if ($sht !== 1) {
                        throw new VerifyException('sighashType must be 1 (SIGHASH_ALL)');
                    }
                    $digest = Tx::sighashLegacy($tx, $idx, $spks[$idx], 1);
                } else {
                    if ($sht !== 1) {
                        throw new VerifyException('sighashType must be 1 (SIGHASH_ALL)');
                    }
                    $digest = Tx::sighashBip143($tx, $idx, self::scriptCode($uin[$idx], $typ, $pk), $amt, 1);
                }
            }
            if (bin2hex($digest) !== bin2hex(U::unhex($ts['digest'], 'digest'))) {
                throw new VerifyException("digest for input $idx does not match the transaction (server digest {$ts['digest']}, local " . bin2hex($digest) . ')');
            }
        }
        return true;
    }

    /**
     * Normalise `expect` (same shape as the JS SDK): chain, from, to (one {address, amount|amountRaw} or a list),
     * change (address or list), token, decimals, opReturn, maxFee (whole units; ETH: ETH), maxFeeSats,
     * maxFeeRaw (wei), maxFeeLimit (TRON sun).
     */
    private static function normExpect(string $chain, ?array $expect): array
    {
        if (!$expect) {
            return [];
        }
        $ex = $expect;
        if (!empty($ex['chain']) && strtolower((string)$ex['chain']) !== $chain) {
            throw new VerifyException("reply is for $chain, expected {$ex['chain']}");
        }
        if (isset($ex['to']) && is_array($ex['to']) && isset($ex['to']['address'])) {
            $ex['to'] = [$ex['to']];
        }
        if (isset($ex['change'])) {
            $ex['allowed'] = array_merge($ex['allowed'] ?? [], is_array($ex['change']) ? $ex['change'] : [$ex['change']]);
        }
        if (Chains::isUtxo($chain)) {
            if (!isset($ex['maxFeeSats']) && isset($ex['maxFee'])) {
                $ex['maxFeeSats'] = gmp_strval(U::units($ex['maxFee'], 8));
            }
        } elseif ($chain === 'eth') {
            if (!isset($ex['maxFeeWei'])) {
                if (isset($ex['maxFeeRaw'])) {
                    $ex['maxFeeWei'] = gmp_strval(U::num($ex['maxFeeRaw']));
                } elseif (isset($ex['maxFee'])) {
                    $ex['maxFeeWei'] = gmp_strval(U::units($ex['maxFee'], 18));
                }
            }
        } elseif (!isset($ex['feeLimit']) && isset($ex['maxFeeLimit'])) {
            $ex['feeLimit'] = gmp_strval(U::num($ex['maxFeeLimit']));
        }
        return $ex;
    }

    /** Data of a simple OP_RETURN <push> script, or null when it is not a single push. */
    private static function opReturnData(string $script): ?string
    {
        $n = strlen($script);
        if ($n >= 2 && ord($script[1]) < 0x4C && ord($script[1]) === $n - 2) {
            return substr($script, 2);
        }
        if ($n >= 3 && ord($script[1]) === 0x4C && ord($script[2]) === $n - 3) {
            return substr($script, 3);
        }
        return null;
    }

    private static function checkUtxoExpect(string $chain, array $outInfo, array $expect, array $inputSpks = []): void
    {
        // change may go back to any address we are spending from, or to an explicitly allowed one
        $allowed = [];
        foreach ($inputSpks as $sp) {
            $allowed[$sp] = true;
        }
        foreach ($expect['allowed'] ?? [] as $a) {
            $allowed[Address::script($chain, $a)[0]] = true;
        }
        $used = array_fill(0, count($outInfo), false);
        foreach ($expect['to'] as $t) {
            $scr = Address::script($chain, $t['address'])[0];
            if (isset($t['amountRaw'])) {
                $amt = U::num($t['amountRaw'], 'amountRaw');
            } elseif (!isset($t['amount'])) {
                throw new VerifyException('expect.to[].amount is required');
            } else {
                $amt = (string)$t['amount'] === 'max' ? null : U::units($t['amount'], 8);
            }
            $wantMax = ($wantMax ?? false) || $amt === null;
            $hit = null;
            foreach ($outInfo as $k => [$a, $v]) {
                if ($used[$k] || $a === null) {
                    continue;
                }
                if (Address::script($chain, $a)[0] === $scr && ($amt === null || gmp_cmp($v, $amt) === 0)) {
                    $hit = $k;
                    break;
                }
            }
            if ($hit === null) {
                throw new VerifyException('the transaction does not pay the requested amount to the requested address');
            }
            $used[$hit] = true;
        }
        $changes = 0;
        foreach ($outInfo as $k => [$a, $v]) {
            if ($used[$k] || $a === null) {
                continue;
            }
            if (!isset($allowed[Address::script($chain, $a)[0]])) {
                throw new VerifyException("output $k pays $a, which is neither a recipient nor an allowed change address");
            }
            $changes++;
        }
        if ($changes && ($wantMax ?? false)) {
            throw new VerifyException('amount "max" must leave no change output');
        }
    }

    /** Accepts ['to'=>'addr','amountUnits'=>n,...] or the list form ['to'=>[['address','amount']],'token','decimals']. */
    private static function acctExpect(string $chain, ?array $expect): array
    {
        $ex = $expect ?? [];
        $to = $ex['to'] ?? null;
        if (is_array($to)) {
            if (count($to) !== 1) {
                throw new VerifyException('account chains take exactly one recipient');
            }
            $ex['to'] = $to[0]['address'];
            if (!isset($ex['amountUnits']) && isset($to[0]['amountRaw'])) {
                $ex['amountUnits'] = gmp_strval(U::num($to[0]['amountRaw'], 'amountRaw'));
            }
            if (!isset($ex['amountUnits'])) {
                $amt = (string)($to[0]['amount'] ?? '');
                if ($amt === 'max') {
                    throw new VerifyException("amount=max cannot be verified on $chain");
                }
                $dec = $ex['decimals'] ?? Rarebl::decimalsFor($chain, $ex['token'] ?? null);
                if ($dec === null) {
                    throw new VerifyException("unknown token decimals for {$ex['token']}; pass expect['decimals']");
                }
                $ex['amountUnits'] = gmp_strval(U::units($amt, (int)$dec));
            }
        }
        return $ex;
    }

    private static function verifyEth(array $u, array $toSign, ?array $expect): bool
    {
        $expect = self::acctExpect('eth', $expect);
        if (($u['to'] ?? null) === null) {
            throw new VerifyException('contract creation is not allowed');
        }
        $chainId = isset($u['chainId']) ? U::num($u['chainId'], 'chainId') : gmp_init(1);
        if (gmp_cmp($chainId, 1) !== 0) {
            throw new VerifyException('chainId ' . gmp_strval($chainId) . ' is not Ethereum mainnet');
        }
        $to = Address::script('eth', $u['to'])[0];
        $nonce = U::num($u['nonce'] ?? 0, 'nonce');
        $gas = U::num($u['gasLimit'] ?? throw new VerifyException('gasLimit missing'), 'gasLimit');
        $mfee = U::num($u['maxFeePerGas'] ?? throw new VerifyException('maxFeePerGas missing'), 'maxFeePerGas');
        $prio = U::num($u['maxPriorityFeePerGas'] ?? 0, 'maxPriorityFeePerGas');
        $value = U::num($u['value'] ?? 0, 'value');
        $data = U::unhex($u['data'] ?? '', 'data');
        $al = [];
        foreach ($u['accessList'] ?? [] as $ent) {
            $keys = [];
            foreach ($ent['storageKeys'] ?? [] as $k) {
                $keys[] = U::unhex($k);
            }
            $al[] = [Address::script('eth', $ent['address'])[0], $keys];
        }
        if (gmp_cmp($prio, $mfee) > 0) {
            throw new VerifyException('maxPriorityFeePerGas exceeds maxFeePerGas');
        }
        $gwei = gmp_init(1000000000);
        if (isset($expect['maxFeeWei'])) {
            if (gmp_cmp($gas * $mfee, gmp_init((string)$expect['maxFeeWei'])) > 0) {
                throw new VerifyException('maximum fee ' . gmp_strval($gas * $mfee) . ' wei exceeds the cap');
            }
        } elseif (gmp_cmp($gas * $mfee, gmp_init('50000000000000000')) > 0) {
            throw new VerifyException('maximum fee ' . gmp_strval($gas * $mfee) . ' wei is above the default cap of 0.05 ETH; pass maxFee to allow it');
        }
        if (isset($expect['maxFeePerGas'])) {
            if (gmp_cmp($mfee, U::num($expect['maxFeePerGas'], 'maxFeePerGas')) > 0) {
                throw new VerifyException('maxFeePerGas ' . gmp_strval($mfee) . ' exceeds the cap');
            }
        } elseif (gmp_cmp($mfee, $gwei * 500) > 0) {
            throw new VerifyException('maxFeePerGas ' . gmp_strval($mfee) . ' wei is above the default cap of 500 gwei; pass maxFeePerGas to allow it');
        }
        if (isset($expect['maxPriorityFeePerGas'])) {
            $tipCap = U::num($expect['maxPriorityFeePerGas'], 'maxPriorityFeePerGas');
        } else {
            $half = gmp_div_q($mfee, 2);
            $tipCap = gmp_cmp($half, $gwei * 5) > 0 ? $half : $gwei * 5;
        }
        if (gmp_cmp($prio, $tipCap) > 0) {
            throw new VerifyException('maxPriorityFeePerGas ' . gmp_strval($prio) . ' is above max(5 gwei, maxFeePerGas/2); pass maxPriorityFeePerGas to allow it');
        }
        if (isset($expect['to'])) {
            $wantTo = Address::script('eth', $expect['to'])[0];
            $amt = gmp_init((string)$expect['amountUnits']);
            if (!empty($expect['token'])) {
                if ($to !== Address::script('eth', $expect['token'])[0] || gmp_sign($value) !== 0) {
                    throw new VerifyException('transaction is not a plain call to the requested token contract');
                }
                $exp = hex2bin('a9059cbb') . str_repeat("\x00", 12) . $wantTo . U::gToBytes($amt);
                if ($data !== $exp) {
                    throw new VerifyException('token transfer calldata does not match the requested recipient and amount');
                }
            } elseif ($to !== $wantTo || gmp_cmp($value, $amt) !== 0 || $data !== '') {
                throw new VerifyException('transaction does not match the requested recipient and amount');
            }
        }
        if (count($toSign) !== 1) {
            throw new VerifyException('an ETH build must have exactly one toSign entry');
        }
        $ts = $toSign[0];
        if (($ts['algorithm'] ?? null) !== 'ecdsa-secp256k1-recoverable') {
            throw new VerifyException('unexpected algorithm for ETH');
        }
        $digest = Hash::keccak256("\x02" . Tx::rlp([$chainId, $nonce, $prio, $mfee, $gas, $to, $value, $data, $al]));
        if (bin2hex($digest) !== bin2hex(U::unhex($ts['digest']))) {
            throw new VerifyException("ETH digest does not match the transaction (server {$ts['digest']}, local " . bin2hex($digest) . ')');
        }
        if (!empty($u['from']) && !empty($ts['address']) && !Address::same('eth', $u['from'], $ts['address'])) {
            throw new VerifyException('toSign address differs from the sender');
        }
        if (isset($expect['from']) && !Address::same('eth', $expect['from'], $u['from'] ?? $ts['address'])) {
            throw new VerifyException('transaction sender is not the requested sender');
        }
        return true;
    }

    private static function verifyTron(array $u, array $toSign, ?array $expect, ?int $nowMs = null): bool
    {
        $expect = self::acctExpect('tron', $expect);
        $raw = U::unhex($u['raw_data_hex'] ?? '', 'raw_data_hex');
        $txid = U::unhex($u['txID'] ?? '', 'txID');
        if ($raw === '') {
            throw new VerifyException('raw_data_hex missing');
        }
        if (Hash::sha256($raw) !== $txid) {
            throw new VerifyException('txID is not sha256(raw_data_hex)');
        }
        $rd = Tx::pbParse($raw);
        $contracts = $rd[11] ?? [];
        if (count($contracts) !== 1) {
            throw new VerifyException('expected exactly one contract');
        }
        $c = Tx::pbParse($contracts[0]);
        $ctype = $c[1][0] ?? 0;
        $param = Tx::pbParse($c[2][0]);
        $body = Tx::pbParse($param[2][0]);
        $owner = $body[1][0] ?? '';
        $expMs = $rd[8][0] ?? null;
        if ($expMs !== null && $expMs <= ($nowMs ?? (int)(microtime(true) * 1000))) {
            throw new VerifyException('transaction has expired (tx_expired)');
        }
        $feeLimit = $rd[18][0] ?? 0;
        $feeCap = isset($expect['feeLimit']) ? (int)$expect['feeLimit'] : 150000000;  // default cap: 150 TRX
        if ($feeLimit > $feeCap) {
            throw new VerifyException("feeLimit $feeLimit sun exceeds the cap $feeCap (default 150 TRX; pass maxFeeLimit to change)");
        }
        $token = null;
        if ($ctype === 1) {
            $kind = 'trx';
            $toB = $body[2][0] ?? '';
            $amount = gmp_init($body[3][0] ?? 0);
        } elseif ($ctype === 31) {
            $kind = 'call';
            $token = $body[2][0] ?? '';
            $data = $body[4][0] ?? '';
            if (($body[3][0] ?? 0) !== 0) {
                throw new VerifyException('TRON call attaches TRX value');
            }
            if (strlen($data) === 68 && substr($data, 0, 4) === hex2bin('a9059cbb') && substr($data, 4, 12) === str_repeat("\x00", 12)) {
                $toB = "\x41" . substr($data, 16, 20);
                $amount = U::bytesToG(substr($data, 36));
            } else {
                throw new VerifyException('TRON call is not a TRC-20 transfer(address,uint256)');
            }
        } else {
            throw new VerifyException("unsupported TRON contract type $ctype");
        }
        if (isset($expect['to'])) {
            if ($toB !== Address::script('tron', $expect['to'])[0] || gmp_cmp($amount, gmp_init((string)$expect['amountUnits'])) !== 0) {
                throw new VerifyException('transaction does not match the requested recipient and amount');
            }
            if (!empty($expect['token'])) {
                if ($kind !== 'call' || $token !== Address::script('tron', $expect['token'])[0]) {
                    throw new VerifyException('transaction is not a call to the requested token contract');
                }
            } elseif ($kind !== 'trx') {
                throw new VerifyException('expected a TRX transfer');
            }
        }
        if (!empty($expect['from']) && $owner !== Address::script('tron', $expect['from'])[0]) {
            throw new VerifyException('transaction owner is not the requested sender');
        }
        if (count($toSign) !== 1) {
            throw new VerifyException('a TRON build must have exactly one toSign entry');
        }
        $ts = $toSign[0];
        if (($ts['algorithm'] ?? null) !== 'ecdsa-secp256k1-recoverable') {
            throw new VerifyException('unexpected algorithm for TRON');
        }
        if (U::unhex($ts['digest']) !== $txid) {
            throw new VerifyException('TRON digest is not the txID');
        }
        if (!empty($ts['address']) && Address::script('tron', $ts['address'])[0] !== $owner) {
            throw new VerifyException('toSign address differs from the transaction owner');
        }
        return true;
    }

    // --- signBuild -----------------------------------------------------------------------

    /**
     * Sign every digest in a build reply.  $keys: one key, a list, or [address => key].
     * Options ($opts):
     *   'expect'         REQUIRED, and it must say who is paid (['to' => [['address' => .., 'amount' => ..]], ...], see
     *                    verifyBuild): without it a compromised server could swap the recipient and you would sign it.
     *   'unsafeNoExpect' true: sign without pinning the recipients (default fee caps still apply)
     *   'verify'         default true; false signs the server's digests blindly and also needs 'unsafeNoExpect' => true
     *   'deterministic'  true: BIP340 (p2tr) with zero aux randomness (reproducible); default random aux
     *   'nowMs', 'prevTxs'  see verifyBuild
     * Returns [['index','signature','publicKey'], ...] for tx/assemble.
     */
    public static function signBuild(array $build, string|array $keys, array $opts = []): array
    {
        Secp::init();
        $verify = (bool)($opts['verify'] ?? true);
        $expect = $opts['expect'] ?? null;
        $unsafe = ($opts['unsafeNoExpect'] ?? false) === true;
        $deterministic = (bool)($opts['deterministic'] ?? false);
        if (!(is_array($expect) && isset($expect['to'])) && !$unsafe) {
            throw new InputException("signBuild needs \$opts['expect'] (['to' => ...]): without it nothing pins who is paid. Pass 'unsafeNoExpect' => true only if you really want to sign without checking the recipients.");
        }
        if (!$verify && !$unsafe) {
            throw new InputException("'verify' => false also needs 'unsafeNoExpect' => true");
        }
        $u = $build['unsigned'];
        $chain = Chains::chain($u['chain']);
        $secrets = [];
        foreach (is_array($keys) ? array_values($keys) : [$keys] as $k) {
            $secrets[] = Keys::parse($chain, $k);
        }
        if (!$secrets) {
            throw new RareblException('no keys supplied');
        }
        $chosen = [];
        foreach ($build['toSign'] as $ts) {
            $idx = (int)$ts['index'];
            $typ = $ts['scriptType'] ?? null;
            $found = null;
            foreach ($secrets as $d) {
                $pub = Secp::pubkeyCreate($d);
                try {
                    if ($chain === 'eth' || $chain === 'tron') {
                        $ok = Address::same($chain, Address::deriveBin($chain, $chain, $pub), $ts['address']);
                    } else {
                        $t = ($typ !== null && in_array($typ, Chains::TYPES[$chain], true)) ? $typ : 'p2pkh';
                        $ok = Address::same($chain, Address::deriveBin($chain, $t, $pub), $ts['address']);
                    }
                } catch (RareblException) {
                    $ok = false;
                }
                if ($ok) {
                    $found = $d;
                    break;
                }
            }
            if ($found === null) {
                throw new KeyMismatchException('no supplied key controls ' . ($ts['address'] ?? '?') . " (digest $idx)");
            }
            $chosen[$idx] = $found;
        }
        if ($verify) {
            $pubs = [];
            foreach ($chosen as $i => $d) {
                $pubs[$i] = Secp::pubkeyCreate($d);
            }
            self::verifyBuild($build, $pubs, $expect, $opts['nowMs'] ?? null, $opts['prevTxs'] ?? null);
        }
        $out = [];
        foreach ($build['toSign'] as $ts) {
            $idx = (int)$ts['index'];
            $d = $chosen[$idx];
            $h = U::unhex($ts['digest'], 'digest');
            $algo = $ts['algorithm'];
            if ($algo === 'ecdsa-secp256k1') {
                $sig = self::signRaw($h, $d, $algo, isset($ts['sighashType']) ? (int)$ts['sighashType'] : 1, $deterministic);
                $pk = Secp::pubkeyCreate($d);
            } elseif ($algo === 'schnorr-bip340') {
                $dt = Secp::taprootTweakSecret($d);
                $sig = self::signRaw($h, $dt, $algo, (int)($ts['sighashType'] ?? 0), $deterministic);
                $pk = U::gToBytes(Secp::pubPoint($dt)[0]);
            } elseif ($algo === 'ecdsa-secp256k1-recoverable') {
                $sig = self::signRaw($h, $d, $algo);
                $pk = Secp::pubkeyCreate($d);
            } else {
                throw new RareblException("unknown algorithm '$algo'");
            }
            $out[] = ['index' => $idx, 'signature' => bin2hex($sig), 'publicKey' => bin2hex($pk)];
        }
        return $out;
    }
}

// ---------------------------------------------------------------------------------------
// webhooks

final class Webhook
{
    /**
     * Check X-Rarebl-Signature: `t=<unix>,v1=<hex HMAC-SHA256(secret, t . "." . body)>`.
     * Pass the RAW request body (file_get_contents('php://input')), not re-encoded JSON.  Returns false (never
     * throws) on a malformed header; $toleranceSec = 0 or null disables the age check.
     */
    public static function verify(string $signingSecret, string $rawBody, string $signatureHeader, ?int $toleranceSec = 300, ?int $now = null): bool
    {
        $t = null;
        $sigs = [];
        foreach (explode(',', $signatureHeader) as $part) {
            $kv = explode('=', trim($part), 2);
            if (count($kv) !== 2) {
                continue;
            }
            if ($kv[0] === 't') {
                $t = $kv[1];
            } elseif ($kv[0] === 'v1') {
                $sigs[] = $kv[1];
            }
        }
        if ($t === null || !$sigs || !ctype_digit($t)) {
            return false;
        }
        if ($toleranceSec && abs(($now ?? time()) - (int)$t) > $toleranceSec) {
            return false;  // $toleranceSec of 0 or null disables the age check, as in the JS SDK
        }
        $mac = hash_hmac('sha256', $t . '.' . $rawBody, $signingSecret);
        foreach ($sigs as $s) {
            if (preg_match('/^[0-9a-fA-F]{64}$/D', $s) === 1 && hash_equals($mac, strtolower($s))) {
                return true;
            }
        }
        return false;
    }
}

// ---------------------------------------------------------------------------------------
// envelope v2 (hosted signing only): X25519 + HKDF-SHA256 + AES-256-GCM

final class Envelope
{
    private const LABEL = 'rarebl-signer-v2';
    private const MAX_TTL = 300;

    private static function need(): void
    {
        foreach (['sodium', 'openssl'] as $ext) {
            if (!extension_loaded($ext)) {
                throw new EnvelopeException("ext-$ext is required for the hosted-signing envelope (local signing does not need it)");
            }
        }
    }

    /** HKDF info of envelope v2: "rarebl-signer-v2" || epk || recipientPub. */
    public static function info(string $epk, string $recipientPub): string
    {
        return self::LABEL . $epk . $recipientPub;
    }

    private static function json(mixed $v): string
    {
        return json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }

    /**
     * Seal JSON (array or string) to an X25519 key with the envelope v2 scheme.  $recipientKey is
     * ['kid' => .., 'publicKey' => base64url].  Used by encrypt(); also what the signer does for address/new with
     * encryptTo.  $esk/$iv are for tests.
     */
    public static function seal(array $recipientKey, array|string $plain, ?string $esk = null, ?string $iv = null): string
    {
        self::need();
        $kid = $recipientKey['kid'] ?? null;
        if (!is_string($kid) || $kid === '') {
            throw new EnvelopeException('signer key needs a kid: pass the whole tx/signer-key reply, not just the public key');
        }
        $spub = U::b64uDec($recipientKey['publicKey']);
        if (strlen($spub) !== 32) {
            throw new EnvelopeException('signer public key must be 32 bytes');
        }
        $esk ??= random_bytes(32);
        $epk = sodium_crypto_scalarmult_base($esk);
        $shared = sodium_crypto_scalarmult($esk, $spub);
        $info = self::info($epk, $spub);
        $key = hash_hkdf('sha256', $shared, 32, $info, '');
        $iv ??= random_bytes(12);
        $pt = is_string($plain) ? $plain : self::json($plain);
        $tag = '';
        $ct = openssl_encrypt($pt, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, $info . $kid, 16);
        if ($ct === false) {
            throw new EnvelopeException('AES-256-GCM encryption failed');
        }
        $env = ['v' => 2, 'kid' => $kid, 'epk' => U::b64u($epk), 'iv' => U::b64u($iv), 'ct' => U::b64u($ct), 'tag' => U::b64u($tag)];
        return U::b64u(self::json($env));
    }

    /**
     * Recipients as the `bind` claim of an envelope: amounts become integer strings in base units (sat / wei / sun /
     * token units).  $to is ['address' => .., 'amount' => whole units | 'max'] or ['address' => .., 'amountRaw' => n],
     * or a list of them.  $decimals is needed for a token that is not a known stablecoin.
     */
    public static function bindOf(string $chain, array $to, ?string $token = null, ?int $decimals = null): array
    {
        $chain = Chains::chain($chain);
        $items = isset($to['address']) ? [$to] : array_values($to);
        if (!$items) {
            throw new EnvelopeException('bind needs at least one recipient');
        }
        $dec = $token ? ($decimals ?? Rarebl::decimalsFor($chain, $token)) : (Rarebl::decimalsFor($chain, null));
        $out = [];
        foreach ($items as $e) {
            if (empty(Address::validate($chain, $e['address'])['valid'])) {
                throw new EnvelopeException("invalid $chain address {$e['address']}");
            }
            if (isset($e['amountRaw'])) {
                $amt = gmp_strval(U::num($e['amountRaw'], 'amountRaw'));
            } elseif (($e['amount'] ?? null) === 'max') {
                $amt = 'max';
            } else {
                if ($dec === null) {
                    throw new EnvelopeException("unknown token decimals for $token; pass decimals");
                }
                $amt = gmp_strval(U::units((string)$e['amount'], $dec));
            }
            $out[] = ['address' => $e['address'], 'amount' => $amt];
        }
        $b = ['to' => $out];
        if ($token) {
            $b['token'] = $token;
        }
        return $b;
    }

    /**
     * Encrypt private keys to the signer's X25519 key for hosted signing, as an envelope v2.
     * $signerKey is the reply of GET /open/tx/signer-key (['kid', 'publicKey']; the kid is required).
     * $payload: 'privateKeys' => [...], 'op' => 'sign'|'send', 'chain' => 'btc', and for op sign 'digests' => [hex, ...]
     * (the toSign digests you verified), for op send 'bind' => Envelope::bindOf(...); optional 'exp' (unix seconds, at most
     * 300 s ahead; default now + 120) and 'jti' (32 lowercase hex; default random).
     * Hosted signing sends your key to Rarebl over TLS; local signing (Signer::signBuild) keeps keys on your side and
     * is recommended.  $esk/$iv/$now are for tests.
     */
    public static function encrypt(array $signerKey, array $payload, ?string $esk = null, ?string $iv = null, ?int $now = null): string
    {
        if (empty($payload['privateKeys']) || !is_array($payload['privateKeys'])) {
            throw new EnvelopeException('payload.privateKeys must be a non-empty list');
        }
        $op = $payload['op'] ?? null;
        if ($op !== 'sign' && $op !== 'send') {
            throw new EnvelopeException("payload.op must be 'sign' or 'send'");
        }
        $chain = $payload['chain'] ?? null;
        if (!is_string($chain) || !isset(Chains::TABLE[$chain])) {
            throw new EnvelopeException('payload.chain is required (btc, ltc, bch, dash, eth or tron)');
        }
        $now ??= time();
        $exp = $payload['exp'] ?? $now + 120;
        if (!is_int($exp) || $exp <= $now || $exp > $now + self::MAX_TTL) {
            throw new EnvelopeException('payload.exp must be within 300 seconds from now');
        }
        $jti = $payload['jti'] ?? bin2hex(random_bytes(16));
        if (preg_match('/^[0-9a-f]{32}$/D', (string)$jti) !== 1) {
            throw new EnvelopeException('payload.jti must be 32 lowercase hex characters');
        }
        $plain = ['v' => 2, 'privateKeys' => array_values($payload['privateKeys']), 'exp' => $exp, 'jti' => $jti, 'op' => $op, 'chain' => $chain];
        if ($op === 'sign') {
            $d = $payload['digests'] ?? null;
            if (!is_array($d) || !$d) {
                throw new EnvelopeException('op sign needs payload.digests (the 32-byte hex digests you intend to sign)');
            }
            foreach ($d as $x) {
                if (!is_string($x) || preg_match('/^[0-9a-fA-F]{64}$/D', $x) !== 1) {
                    throw new EnvelopeException('op sign needs payload.digests (the 32-byte hex digests you intend to sign)');
                }
            }
            $plain['digests'] = array_map('strtolower', array_values($d));
        } else {
            $bd = $payload['bind'] ?? null;
            if (!is_array($bd) || empty($bd['to'])) {
                throw new EnvelopeException('op send needs payload.bind (see Envelope::bindOf)');
            }
            $plain['bind'] = $bd;
        }
        return self::seal($signerKey, $plain, $esk, $iv);
    }

    /**
     * Open an envelope v2 with the recipient's X25519 secret key (32 raw bytes or 64 hex chars): the signer's key for
     * a request envelope (tests, signer implementations), or your own encryptTo key for the encryptedPrivateKey of
     * address/new.
     */
    public static function decrypt(string $secretKey, string $envelope): array
    {
        self::need();
        if (strlen($secretKey) === 64 && ctype_xdigit($secretKey)) {
            $secretKey = (string)hex2bin($secretKey);
        }
        $env = json_decode(U::b64uDec($envelope), true, 8, JSON_THROW_ON_ERROR);
        if (($env['v'] ?? null) !== 2) {
            throw new EnvelopeException('unsupported envelope version (v2 is required)');
        }
        $epk = U::b64uDec($env['epk']);
        $info = self::info($epk, sodium_crypto_scalarmult_base($secretKey));
        $key = hash_hkdf('sha256', sodium_crypto_scalarmult($secretKey, $epk), 32, $info, '');
        $pt = openssl_decrypt(U::b64uDec($env['ct']), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, U::b64uDec($env['iv']), U::b64uDec($env['tag']), $info . (string)$env['kid']);
        if ($pt === false) {
            throw new EnvelopeException('envelope authentication failed');
        }
        return json_decode($pt, true, 16, JSON_THROW_ON_ERROR);
    }
}

// ---------------------------------------------------------------------------------------
// HTTP client

final class Rarebl
{
    public const DEFAULT_BASE_URL = 'https://api.rarebl.com';
    private const NATIVE_DECIMALS = ['btc' => 8, 'ltc' => 8, 'bch' => 8, 'dash' => 8, 'eth' => 18, 'tron' => 6];
    private const TOKEN_DECIMALS = [
        'eth:0xdac17f958d2ee523a2206206994597c13d831ec7' => 6,  // USDT
        'eth:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' => 6,  // USDC
        'tron:TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t' => 6,         // USDT
    ];

    private string $baseUrl;
    private int $timeout;
    private string $userAgent;
    /** @var callable|null fn(string $method, string $url, array $headers, ?string $body): array{0:int,1:string} */
    private $transport;

    /** @param array{baseUrl?:string,timeout?:int,userAgent?:string,transport?:callable} $opts */
    public function __construct(array $opts = [])
    {
        $this->baseUrl = rtrim($opts['baseUrl'] ?? self::DEFAULT_BASE_URL, '/');
        $this->timeout = (int)($opts['timeout'] ?? 30);
        $this->userAgent = $opts['userAgent'] ?? ('rarebl-php/' . VERSION);
        $this->transport = $opts['transport'] ?? null;
    }

    private function call(string $method, string $path, ?array $params = null, ?array $body = null, array $headers = []): mixed
    {
        $url = $this->baseUrl . $path;
        if ($method === 'GET' && $params) {
            $url .= '?' . http_build_query(array_filter($params, fn($v) => $v !== null));
        }
        $hdrs = ['Accept: application/json', 'User-Agent: ' . $this->userAgent];
        $payload = null;
        if ($body !== null) {
            $payload = json_encode($body, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            $hdrs[] = 'Content-Type: application/json';
        }
        foreach ($headers as $k => $v) {
            $hdrs[] = "$k: $v";
        }
        if ($this->transport !== null) {
            [$status, $raw] = ($this->transport)($method, $url, $hdrs, $payload);
        } else {
            if (!extension_loaded('curl')) {
                throw new RareblException('ext-curl is required for the HTTP client');
            }
            $ch = curl_init($url);
            curl_setopt_array($ch, [CURLOPT_CUSTOMREQUEST => $method, CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => $hdrs,
                CURLOPT_TIMEOUT => $this->timeout, CURLOPT_CONNECTTIMEOUT => min(10, $this->timeout), CURLOPT_FOLLOWLOCATION => false]);
            if ($payload !== null) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
            }
            $raw = curl_exec($ch);
            if ($raw === false) {
                $err = curl_error($ch);
                throw new RareblException("network error: $err");
            }
            $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            // No curl_close(): deprecated in PHP 8.5; the handle is freed when $ch goes out of scope (PHP 8+).
        }
        $env = json_decode((string)$raw, true, 512, JSON_BIGINT_AS_STRING);
        if (!is_array($env)) {
            throw new ApiException('HTTP' . $status, 'non-JSON reply', null, null, $status);
        }
        $code = $env['code'] ?? null;
        if (($env['status'] ?? null) !== 1 || ($code && $code !== 'API200') || $status >= 400) {
            $d = is_array($env['data'] ?? null) ? $env['data'] : [];
            throw new ApiException((string)($code ?: 'HTTP' . $status), (string)($env['message'] ?? ''),
                isset($d['reason']) ? (string)$d['reason'] : null, isset($d['detail']) ? (string)$d['detail'] : null, $status, $env['data'] ?? null);
        }
        return $env['data'] ?? null;
    }

    public function get(string $path, array $params = []): mixed
    {
        return $this->call('GET', $path, $params);
    }

    public function post(string $path, array $body, array $headers = []): mixed
    {
        return $this->call('POST', $path, null, $body, $headers);
    }

    public function build(array $req): array
    {
        return $this->post('/open/tx/build', $req);
    }

    public function assemble(array $unsigned, array $signatures, bool $broadcast = false): array
    {
        return $this->post('/open/tx/assemble', ['unsigned' => $unsigned, 'signatures' => $signatures, 'broadcast' => $broadcast]);
    }

    /** $hexOrTx: signed hex string, or (TRON) the signed tx array. */
    public function broadcast(string $chain, string|array $hexOrTx, ?string $idempotencyKey = null): array
    {
        $body = ['chain' => $chain];
        $body[is_array($hexOrTx) ? 'tx' : 'hex'] = $hexOrTx;
        return $this->post('/open/tx/broadcast', $body, $idempotencyKey ? ['Idempotency-Key' => $idempotencyKey] : []);
    }

    public function estimate(array $req): array
    {
        return $this->post('/open/tx/estimate', $req);
    }

    public function decode(string $chain, string|array $hexOrTx): array
    {
        $body = ['chain' => $chain];
        $body[is_array($hexOrTx) ? 'tx' : 'hex'] = $hexOrTx;
        return $this->post('/open/tx/decode', $body);
    }

    public function watch(string $chain, array $addresses): array
    {
        return $this->post('/open/address/watch', ['chain' => $chain, 'addresses' => array_values($addresses)]);
    }

    public function utxos(string $chain, string $address, ?int $minConf = null): array
    {
        return $this->get('/open/address/utxos', ['chain' => $chain, 'address' => $address, 'minConf' => $minConf]);
    }

    public function status(string $chain, string $txid): array
    {
        return $this->get('/open/tx/status', ['chain' => $chain, 'id' => $txid]);
    }

    public function nonce(string $address): array
    {
        return $this->get('/open/address/nonce', ['chain' => 'eth', 'address' => $address]);
    }

    public function validate(string $chain, string $address): array
    {
        return $this->get('/open/address/validate', ['chain' => $chain, 'address' => $address]);
    }

    public function price(string|array $assets, string $quote = 'usd'): array
    {
        return $this->get('/open/market/price', ['assets' => is_array($assets) ? implode(',', $assets) : $assets, 'quote' => $quote]);
    }

    public function signerKey(): array
    {
        return $this->get('/open/tx/signer-key');
    }

    public function outspends(string $chain, string $txid): array
    {
        return $this->get('/open/tx/outspends', ['chain' => $chain, 'id' => $txid]);
    }

    /**
     * The safe path: build -> verify -> sign locally -> assemble + broadcast.
     * Options: chain, from, to, amount (decimal string, whole units, or "max"), key (hex/WIF, a list,
     * or [address => key]), feeRate | priority, token, decimals, verify (default true), broadcast
     * (default true), autoWatch (default true), change, maxFee (cap in sats/wei/sun), maxFeeRate (UTXO sat/vB;
     * default caps are in Signer::verifyBuild); verify=false signs without any check; any other
     * option is passed through to tx/build.  Returns the txid (or the `signed` array when broadcast=false).
     * Keys are used locally and never sent.
     */
    public function transfer(array $o): string|array|null
    {
        $chain = Chains::chain($o['chain'] ?? throw new RareblException('chain is required'));
        $from = $o['from'] ?? throw new RareblException('from is required');
        $to = $o['to'] ?? throw new RareblException('to is required');
        $amount = (string)($o['amount'] ?? throw new RareblException('amount is required'));
        $key = $o['key'] ?? throw new RareblException('key is required');
        $verify = $o['verify'] ?? true;
        $broadcast = $o['broadcast'] ?? true;
        $token = $o['token'] ?? null;
        $req = ['chain' => $chain];
        if (Chains::isUtxo($chain)) {
            $req += ['from' => [$from], 'to' => [['address' => $to, 'amount' => $amount]]];
            if (!empty($o['change'])) {
                $req['change'] = $o['change'];
            }
        } else {
            $req += ['from' => $from, 'to' => $to, 'amount' => $amount];
            if ($token) {
                $req['token'] = $token;
            }
        }
        if (isset($o['feeRate'])) {
            $req['feeRate'] = (string)$o['feeRate'];
        } elseif (!empty($o['priority'])) {
            $req['priority'] = $o['priority'];
        }
        $own = ['chain', 'from', 'to', 'amount', 'key', 'verify', 'broadcast', 'token', 'decimals', 'autoWatch', 'change', 'maxFee', 'maxFeeRate', 'feeRate', 'priority'];
        foreach ($o as $k => $v) {
            if (!in_array($k, $own, true)) {
                $req[$k] = $v;
            }
        }
        $build = $this->buildWithWatch($req, $chain, $from, $o['autoWatch'] ?? true);
        $expect = $verify ? $this->expect($chain, $from, $to, $amount, $token, $o['decimals'] ?? null, $o['change'] ?? null, $o['maxFee'] ?? null) : null;
        if ($expect !== null && isset($o['maxFeeRate'])) {
            $expect['maxFeeRate'] = $o['maxFeeRate'];
        }
        $sigs = Signer::signBuild($build, $key, ['verify' => (bool)$verify, 'expect' => $expect, 'unsafeNoExpect' => !$verify]);
        $res = $this->assemble($build['unsigned'], $sigs, (bool)$broadcast);
        if (!$broadcast) {
            return $res['signed'] ?? null;
        }
        return $res['broadcast']['txid'] ?? ($res['signed']['txid'] ?? null);
    }

    private function buildWithWatch(array $req, string $chain, string $from, bool $autoWatch): array
    {
        for ($attempt = 0; $attempt < 25; $attempt++) {
            try {
                return $this->build($req);
            } catch (ApiException $e) {
                if (!($autoWatch && $e->reason === 'not_watched' && Chains::isUtxo($chain) && $attempt < 24)) {
                    throw $e;
                }
                if ($attempt === 0) {
                    $this->watch($chain, [$from]);
                }
                sleep(3);
            }
        }
        throw new RareblException('address watch did not become active');
    }

    /** Known decimals: native coins and the listed stablecoins; null for an unknown token. */
    public static function decimalsFor(string $chain, ?string $token): ?int
    {
        if (!$token) {
            return self::NATIVE_DECIMALS[$chain] ?? null;
        }
        return self::TOKEN_DECIMALS[$chain . ':' . ($chain === 'eth' ? strtolower($token) : $token)] ?? null;
    }

    private function expect(string $chain, string $from, string $to, string $amount, ?string $token, ?int $decimals, ?string $change, mixed $maxFee): array
    {
        if (Chains::isUtxo($chain)) {
            $ex = ['to' => [['address' => $to, 'amount' => $amount]], 'allowed' => [$change ?: $from]];
            if ($maxFee !== null) {
                $ex['maxFeeSats'] = (string)$maxFee;
            }
            return $ex;
        }
        if ($amount === 'max') {
            throw new VerifyException("amount=max cannot be verified on $chain; pass an exact amount");
        }
        if ($token) {
            $dec = $decimals ?? self::TOKEN_DECIMALS[$chain . ':' . ($chain === 'eth' ? strtolower($token) : $token)] ?? null;
            if ($dec === null) {
                throw new RareblException("unknown token decimals for $token; pass 'decimals'");
            }
        } else {
            $dec = self::NATIVE_DECIMALS[$chain];
        }
        $ex = ['to' => $to, 'amountUnits' => gmp_strval(U::units($amount, $dec)), 'token' => $token, 'from' => $from];
        if ($maxFee !== null) {
            $ex[$chain === 'eth' ? 'maxFeeWei' : 'feeLimit'] = (string)$maxFee;
        }
        return $ex;
    }
}
