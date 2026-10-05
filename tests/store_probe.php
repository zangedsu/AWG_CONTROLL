<?php
declare(strict_types=1);
require dirname(__DIR__) . '/app/Store.php';

function check(bool $condition, string $message): void {
    if (!$condition) throw new RuntimeException($message);
}
function rejects(callable $fn, string $message): void {
    try { $fn(); } catch (RuntimeException) { return; }
    throw new RuntimeException($message);
}

$dir = $argv[1];
$store = new Store($dir);
check((fileperms($dir) & 0777) === 0700, 'Storage directory must be private');
check((fileperms($dir . '/secret.key') & 0777) === 0600, 'Encryption key must be private');

$credential = 'fixture-secret-with-unicode-ключ';
$a = $store->encrypt($credential);
$b = $store->encrypt($credential);
check($a !== $b && !str_contains($a, $credential), 'Credentials need unique nonces and ciphertext');
check($store->decrypt($a) === $credential, 'Credential must decrypt');
$raw = base64_decode($a, true);
$raw[strlen($raw) - 1] = chr(ord($raw[strlen($raw) - 1]) ^ 1);
rejects(fn() => $store->decrypt(base64_encode($raw)), 'Tampered ciphertext must fail closed');
rejects(fn() => $store->decrypt('invalid'), 'Malformed credential must fail closed');

$store->write('fixture', ['name' => 'Клиент', 'credential' => $a]);
check($store->read('fixture')['name'] === 'Клиент', 'Store should preserve Unicode data');
check((fileperms($dir . '/fixture.json') & 0777) === 0600, 'Credential records must be private');
rejects(fn() => $store->write('../escape', ['bad' => true]), 'Path traversal must be rejected');
file_put_contents($dir . '/broken.json', '{bad');
rejects(fn() => $store->read('broken'), 'Corrupted data must not silently erase profiles');

echo "Store security checks passed\n";
