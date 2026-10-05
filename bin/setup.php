<?php
declare(strict_types=1);
// CLI-only initialization. Credentials arrive on stdin and are encrypted immediately.
if (PHP_SAPI !== 'cli') exit(1);
require dirname(__DIR__) . '/app/App.php';
$input = json_decode(stream_get_contents(STDIN), true, 32, JSON_THROW_ON_ERROR);
$app = new App();
$server = $app->saveServer($input);
if (!empty($input['known_hosts_file']) && !empty($input['fingerprint'])) {
    $servers = $app->store->read('servers');
    $entry = file_get_contents($input['known_hosts_file']);
    file_put_contents($servers[$server['id']]['known_hosts_path'], $entry, LOCK_EX); chmod($servers[$server['id']]['known_hosts_path'], 0600);
    $servers[$server['id']]['fingerprint'] = $input['fingerprint']; $app->store->write('servers', $servers);
}
echo json_encode(['id' => $server['id'], 'host' => $server['host'], 'read_only' => $server['read_only']]) . "\n";
