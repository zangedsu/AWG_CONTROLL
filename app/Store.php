<?php
declare(strict_types=1);

final class Store
{
    private string $dir;
    private string $key;

    public function __construct(string $dir)
    {
        $this->dir = $dir;
        if (!is_dir($dir)) mkdir($dir, 0700, true);
        chmod($dir, 0700);
        $keyFile = $dir . '/secret.key';
        if (!is_file($keyFile)) {
            $handle = @fopen($keyFile, 'x');
            if ($handle) { chmod($keyFile, 0600); fwrite($handle, random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES)); fclose($handle); }
        }
        $this->key = (string) file_get_contents($keyFile);
        if (strlen($this->key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) throw new RuntimeException('Повреждён локальный ключ хранилища.');
    }

    public function path(string $name): string
    {
        if (!preg_match('/^[a-zA-Z0-9_.-]+$/', $name)) throw new RuntimeException('Invalid storage name');
        return $this->dir . '/' . $name;
    }

    public function read(string $name, mixed $default = []): mixed
    {
        $path = $this->path($name . '.json');
        if (!is_file($path)) return $default;
        $handle = fopen($path, 'r'); flock($handle, LOCK_SH);
        $raw = stream_get_contents($handle); flock($handle, LOCK_UN); fclose($handle);
        try { return json_decode($raw, true, 128, JSON_THROW_ON_ERROR); }
        catch (JsonException) { throw new RuntimeException('Повреждено локальное хранилище: ' . $name); }
    }

    public function write(string $name, mixed $value): void
    {
        $path = $this->path($name . '.json');
        $tmp = $path . '.' . bin2hex(random_bytes(5));
        file_put_contents($tmp, json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT), LOCK_EX);
        chmod($tmp, 0600); rename($tmp, $path);
    }

    public function encrypt(string $secret): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        return base64_encode($nonce . sodium_crypto_secretbox($secret, $nonce, $this->key));
    }

    public function decrypt(string $sealed): string
    {
        $raw = base64_decode($sealed, true);
        if ($raw === false || strlen($raw) < 40) throw new RuntimeException('Invalid credential');
        $plain = sodium_crypto_secretbox_open(substr($raw, 24), substr($raw, 0, 24), $this->key);
        if ($plain === false) throw new RuntimeException('Не удалось расшифровать SSH-доступ.');
        return $plain;
    }

    public function audit(string $event, string $server, string $status, array $detail = []): void
    {
        $entry = ['id' => bin2hex(random_bytes(6)), 'timestamp' => gmdate('c'), 'event' => $event, 'server' => $server, 'status' => $status, 'detail' => $detail];
        $path = $this->path('audit.jsonl');
        file_put_contents($path, json_encode($entry, JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND | LOCK_EX);
        chmod($path, 0600);
        if (filesize($path) > 4000000) {
            $lines = file($path, FILE_IGNORE_NEW_LINES); file_put_contents($path, implode("\n", array_slice($lines, -2000)) . "\n", LOCK_EX);
        }
    }

    public function auditEntries(): array
    {
        $path = $this->path('audit.jsonl');
        if (!is_file($path)) return [];
        return array_values(array_reverse(array_filter(array_map(fn($line) => json_decode($line, true), array_slice(file($path, FILE_IGNORE_NEW_LINES), -300)))));
    }
}
