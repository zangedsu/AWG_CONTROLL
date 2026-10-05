<?php
declare(strict_types=1);
require_once __DIR__ . '/Store.php';
require_once __DIR__ . '/Demo.php';

final class ApiError extends RuntimeException
{
    public function __construct(public string $errorCode, string $message, public int $status = 400) { parent::__construct($message); }
}

final class App
{
    public const PROTECTED_HOST = '192.0.2.10';
    public Store $store;
    private string $root;

    public function __construct(?string $directory = null)
    {
        $this->root = dirname(__DIR__);
        $this->store = new Store($directory ?? (getenv('AWG_DATA_DIR') ?: $this->root . '/var/private'));
    }

    public function bootstrap(): array
    {
        $servers = $this->store->read('servers');
        return ['csrf' => $_SESSION['csrf'] ?? '', 'mode' => count($servers) ? 'live' : 'demo', 'active_server_id' => array_key_first($servers),
            'servers' => array_values(array_map([$this, 'publicServer'], $servers)), 'poll_interval' => 5,
            'capabilities' => ['monitoring', 'clients', 'containers', 'services', 'logs', 'network', 'action_plans', 'audit', 'diagnostics'],
            'version' => '1.0.0', 'sources' => ['https://docs.amnezia.org/', 'https://github.com/amnezia-vpn/amnezia-client', 'https://canvasui.dev/']];
    }

    public function publicServer(array $server): array
    {
        return ['id' => $server['id'], 'name' => $server['name'], 'host' => $server['host'], 'port' => $server['port'], 'username' => $server['username'],
            'read_only' => $this->isReadOnly($server), 'protected' => $server['host'] === self::PROTECTED_HOST,
            'auth_type' => empty($server['key_path']) ? 'password' : 'key', 'key_path' => $server['key_path'] ?? '',
            'has_password' => !empty($server['password_encrypted']), 'pinned' => !empty($server['fingerprint']), 'fingerprint' => $server['fingerprint'] ?? null];
    }

    public function server(string $id): array
    {
        $servers = $this->store->read('servers');
        if (!isset($servers[$id])) throw new ApiError('server_not_found', 'Сервер не найден. Добавьте SSH-подключение в настройках.', 404);
        return $servers[$id];
    }

    public function isReadOnly(array $server): bool
    {
        return $server['host'] === self::PROTECTED_HOST || ($server['read_only'] ?? true) !== false;
    }

    public function saveServer(array $input): array
    {
        $servers = $this->store->read('servers');
        $id = (string) ($input['id'] ?? bin2hex(random_bytes(6)));
        if (!preg_match('/^[a-zA-Z0-9_-]{1,64}$/', $id)) throw new ApiError('invalid_server', 'Некорректный идентификатор сервера.');
        $old = $servers[$id] ?? [];
        $host = trim((string) ($input['host'] ?? $old['host'] ?? ''));
        if (!preg_match('/^(?:[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}|[a-fA-F0-9:]+)$/', $host) || str_contains($host, '..')) throw new ApiError('invalid_host', 'Укажите IP-адрес или DNS-имя без схемы и пути.');
        $username = (string) ($input['username'] ?? $old['username'] ?? 'root');
        if (!preg_match('/^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}$/', $username)) throw new ApiError('invalid_user', 'Некорректное имя SSH-пользователя.');
        $port = filter_var($input['port'] ?? $old['port'] ?? 22, FILTER_VALIDATE_INT);
        if (!$port || $port < 1 || $port > 65535) throw new ApiError('invalid_port', 'SSH-порт должен быть от 1 до 65535.');
        $name = trim((string) ($input['name'] ?? $old['name'] ?? $host));
        if (!$name || mb_strlen($name) > 80) throw new ApiError('invalid_name', 'Имя сервера: от 1 до 80 символов.');
        $server = ['id' => $id, 'name' => $name, 'host' => $host, 'port' => $port, 'username' => $username,
            'read_only' => $host === self::PROTECTED_HOST || ($input['read_only'] ?? $old['read_only'] ?? true) !== false,
            'key_path' => (string) ($input['key_path'] ?? $old['key_path'] ?? ''), 'fingerprint' => $old['fingerprint'] ?? null,
            'known_hosts_path' => $this->store->path('known_hosts.' . $id), 'password_encrypted' => $old['password_encrypted'] ?? null];
        if (!empty($input['password'])) $server['password_encrypted'] = $this->store->encrypt((string) $input['password']);
        if ($old && ($old['host'] !== $host || $old['port'] !== $port)) { $server['fingerprint'] = null; @unlink($server['known_hosts_path']); }
        $servers[$id] = $server;
        $this->store->write('servers', $servers);
        $this->store->audit('server.saved', $id, 'success', ['host' => $host, 'read_only' => $server['read_only']]);
        return $this->publicServer($server);
    }

    public function fingerprint(string $id): array
    {
        return $this->engine('fingerprint', $this->server($id));
    }

    public function trust(string $id, string $fingerprint): array
    {
        $server = $this->server($id);
        $data = $this->engine('fingerprint', $server);
        $keys = $data['keys'] ?? [$data];
        $found = null;
        foreach ($keys as $key) if (hash_equals((string) ($key['fingerprint'] ?? ''), $fingerprint)) { $found = $key; break; }
        if (!$found) throw new ApiError('fingerprint_changed', 'SSH-ключ изменился. Сверьте новый отпечаток в консоли провайдера.');
        if (empty($found['known_hosts_entry'])) throw new ApiError('invalid_fingerprint', 'Сервер не предоставил SSH-ключ.');
        file_put_contents($server['known_hosts_path'], $found['known_hosts_entry'] . "\n", LOCK_EX); chmod($server['known_hosts_path'], 0600);
        $servers = $this->store->read('servers'); $servers[$id]['fingerprint'] = $fingerprint; $this->store->write('servers', $servers);
        $this->store->audit('ssh.key.pinned', $id, 'success', ['fingerprint' => $fingerprint]);
        return $this->publicServer($servers[$id]);
    }

    public function engine(string $operation, array $server, array $params = []): array
    {
        $server['read_only'] = $this->isReadOnly($server);
        if (empty($server['key_path']) && !empty($server['password_encrypted'])) $server['password'] = $this->store->decrypt($server['password_encrypted']);
        unset($server['password_encrypted']);
        $payload = json_encode(['operation' => $operation, 'server' => $server, 'params' => $params], JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE);
        $process = proc_open(['python3', $this->root . '/scripts/remote.py'], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $this->root);
        if (!is_resource($process)) throw new ApiError('engine_failed', 'Не удалось запустить SSH-модуль.', 503);
        fwrite($pipes[0], $payload); fclose($pipes[0]);
        stream_set_blocking($pipes[1], false); stream_set_blocking($pipes[2], false);
        $out = ''; $err = ''; $timeout = $operation === 'execute' ? (($params['action'] ?? '') === 'container.update' ? 360 : 150) : 85;
        $deadline = microtime(true) + $timeout;
        while (true) {
            $out .= stream_get_contents($pipes[1]); $err .= stream_get_contents($pipes[2]);
            $status = proc_get_status($process);
            if (!$status['running']) break;
            if (microtime(true) > $deadline || strlen($out) > 8000000 || strlen($err) > 50000) {
                proc_terminate($process); fclose($pipes[1]); fclose($pipes[2]); proc_close($process);
                throw new ApiError('ssh_timeout', 'SSH-запрос превысил лимит времени или объёма.', 504);
            }
            usleep(30000);
        }
        $out .= stream_get_contents($pipes[1]); fclose($pipes[1]); fclose($pipes[2]); proc_close($process);
        $result = json_decode($out, true);
        if (!is_array($result)) throw new ApiError('engine_failed', 'SSH-модуль вернул некорректный ответ. Проверьте Python 3 и OpenSSH.', 502);
        if (($result['ok'] ?? false) !== true) {
            $error = $result['error'] ?? 'SSH-запрос не выполнен.';
            $message = is_array($error) ? (string) ($error['message'] ?? 'SSH-запрос не выполнен.') : (string) $error;
            throw new ApiError(is_array($error) ? (string) ($error['code'] ?? $result['code'] ?? 'ssh_error') : (string) ($result['code'] ?? 'ssh_error'), $message, 502);
        }
        return $result['data'] ?? [];
    }

    public function snapshot(string $id, string $mode, bool $force = false): array
    {
        if ($mode === 'demo') return Demo::snapshot();
        $server = $this->server($id);
        if (empty($server['fingerprint'])) throw new ApiError('host_key_required', 'Подтвердите SSH-отпечаток сервера в настройках.', 409);
        $cache = $this->store->read('snapshot.' . $id, null);
        if (!$force && $cache && time() - $cache['cached_at'] < 4) return $cache['data'];
        $lock = fopen($this->store->path('snapshot.' . $id . '.lock'), 'c'); chmod($this->store->path('snapshot.' . $id . '.lock'), 0600);
        flock($lock, LOCK_EX);
        try {
            $cache = $this->store->read('snapshot.' . $id, null);
            if (!$force && $cache && time() - $cache['cached_at'] < 4) return $cache['data'];
            $data = $this->engine('snapshot', $server);
            $data['server'] = $this->publicServer($server);
            foreach ($data['clients'] ?? [] as $index => $client) {
                $data['clients'][$index]['id'] = hash('sha256', ($client['container'] ?? '') . ($client['interface'] ?? '') . ($client['public_key'] ?? ''));
            }
            $history = $cache['data']['history'] ?? [];
            $host = $data['host'] ?? []; $net = $host['network'] ?? []; $now = time();
            $prev = $history ? end($history) : null; $elapsed = $prev ? max(1, $now - $prev['timestamp']) : 1;
            $point = ['timestamp' => $now, 'cpu_percent' => $host['cpu_percent'] ?? null, 'memory_percent' => $host['memory']['percent'] ?? null,
                'rx_bytes' => $net['rx_bytes'] ?? 0, 'tx_bytes' => $net['tx_bytes'] ?? 0,
                'rx_bps' => $prev ? max(0, (($net['rx_bytes'] ?? 0) - $prev['rx_bytes']) / $elapsed) : null,
                'tx_bps' => $prev ? max(0, (($net['tx_bytes'] ?? 0) - $prev['tx_bytes']) / $elapsed) : null];
            $history[] = $point; $data['history'] = array_slice($history, -120);
            $data['host']['network']['rx_bps'] = $point['rx_bps']; $data['host']['network']['tx_bps'] = $point['tx_bps'];
            $data['cached_at'] = gmdate('c');
            $this->store->write('snapshot.' . $id, ['cached_at' => $now, 'data' => $data]);
            return $data;
        } finally { flock($lock, LOCK_UN); fclose($lock); }
    }

    public function logs(string $id, string $mode, array $input): array
    {
        $lines = max(20, min(2000, (int) ($input['lines'] ?? 200)));
        $source = (string) ($input['source'] ?? 'journal');
        if ($mode === 'demo') $data = Demo::logs($source, $lines);
        else {
            $snapshot = $this->snapshot($id, $mode);
            $sources = $snapshot['logs']['sources'] ?? [];
            if (!in_array($source, array_column($sources, 'id'), true)) throw new ApiError('invalid_log_source', 'Источник логов недоступен. Обновите список.', 404);
            $data = $this->engine('logs', $this->server($id), ['source' => $source, 'lines' => $lines, 'since' => (string) ($input['since'] ?? ''), 'priority' => (string) ($input['priority'] ?? '')]);
        }
        $query = mb_substr((string) ($input['query'] ?? ''), 0, 200);
        if ($query !== '') {
            $filtered = array_values(array_filter(explode("\n", $data['text'] ?? ''), fn($line) => mb_stripos($line, $query) !== false));
            $data['text'] = implode("\n", $filtered); $data['lines'] = $filtered;
        }
        return $data;
    }

    public function plan(array $input): array
    {
        $mode = ($input['mode'] ?? 'live') === 'demo' ? 'demo' : 'live';
        $id = (string) ($input['server_id'] ?? '');
        $action = (string) ($input['action'] ?? '');
        $target = (string) ($input['target'] ?? '');
        $params = $input['params'] ?? [];
        if (!is_array($params)) throw new ApiError('invalid_params', 'Некорректные параметры операции.');
        $supported = ['client.create', 'client.delete', 'client.revoke', 'client.rename', 'container.restart', 'container.stop', 'container.start', 'container.update', 'service.restart', 'service.stop', 'service.start', 'server.reboot', 'server.update', 'server.backup'];
        if (!in_array($action, $supported, true)) throw new ApiError('unknown_action', 'Неизвестная операция.');
        $normalized = $action === 'server.reboot' ? 'host.reboot' : ($action === 'client.revoke' ? 'client.delete' : $action);
        $params['action'] = $normalized;
        if (str_starts_with($action, 'container.')) $params['container'] ??= $target;
        if (str_starts_with($action, 'service.')) $params['service'] ??= $target;
        if ($mode === 'demo') {
            $server = ['host' => 'demo.local', 'read_only' => true];
            $plan = ['summary' => 'Предпросмотр операции в демонстрационном режиме', 'commands' => [], 'warnings' => ['Демонстрационные данные. Операция не будет отправлена на сервер.'], 'executable' => false];
        } else {
            $server = $this->server($id);
            if ($action === 'server.update' || $action === 'server.backup') {
                $plan = ['summary' => $action === 'server.update' ? 'Обновление ОС требует проверки пакетов и отдельного окна обслуживания.' : 'Экспорт диагностики доступен без изменений. Полная резервная копия секретов требует отдельного защищённого процесса.',
                    'commands' => [], 'warnings' => ['Эта операция автоматически не выполняется.'], 'executable' => false];
            } else $plan = $this->engine('plan', $server, $params);
        }
        $readOnly = $mode === 'demo' || $this->isReadOnly($server);
        $plan = array_merge($plan, ['plan_id' => bin2hex(random_bytes(16)), 'action' => $action, 'target' => $target, 'read_only' => $readOnly,
            'executable' => !$readOnly && ($plan['executable'] ?? false), 'expires_at' => gmdate('c', time() + 600)]);
        if ($readOnly) $plan['warnings'][] = 'Режим «только чтение»: выполнение изменений заблокировано серверной политикой.';
        if (!empty($plan['precondition'])) $params['expected_precondition'] = $plan['precondition'];
        $stored = ['public' => $plan, 'params' => $params, 'server_id' => $id, 'mode' => $mode, 'expires' => time() + 600,
            'server_hash' => hash('sha256', json_encode($server)), 'session' => hash('sha256', session_id())];
        $this->store->write('plan.' . $plan['plan_id'], $stored);
        $this->store->audit('action.planned', $id, 'preview', ['action' => $action, 'target' => $target, 'executable' => $plan['executable']]);
        return $plan;
    }

    public function execute(array $input): array
    {
        $id = (string) ($input['plan_id'] ?? '');
        if (!preg_match('/^[a-f0-9]{32}$/', $id)) throw new ApiError('invalid_plan', 'Некорректный план операции.');
        $path = $this->store->path('plan.' . $id . '.lock'); $lock = fopen($path, 'c'); chmod($path, 0600); flock($lock, LOCK_EX);
        try {
            $plan = $this->store->read('plan.' . $id, null);
            if (!$plan || !hash_equals($plan['session'], hash('sha256', session_id()))) throw new ApiError('plan_not_found', 'План не найден. Создайте новый план.', 404);
            if ($plan['expires'] < time() || !empty($plan['consumed'])) throw new ApiError('plan_expired', 'План истёк или уже использован.', 409);
            if ($plan['mode'] === 'demo' || !$plan['public']['executable']) throw new ApiError('read_only', 'Выполнение заблокировано: сервер доступен только для чтения.', 403);
            $server = $this->server($plan['server_id']);
            if ($this->isReadOnly($server)) throw new ApiError('read_only', 'Изменения сервера запрещены политикой.', 403);
            if (!hash_equals($plan['server_hash'], hash('sha256', json_encode($server)))) throw new ApiError('server_changed', 'Настройки подключения изменились. Создайте новый план.', 409);
            if (!hash_equals($plan['public']['target'], (string) ($input['confirmation'] ?? ''))) throw new ApiError('confirmation_required', 'Для подтверждения введите имя цели из плана.');
            $plan['consumed'] = true; $this->store->write('plan.' . $id, $plan);
            $params = $plan['params']; $params['confirmed'] = true;
            try {
                $result = $this->engine('execute', $server, $params);
                $this->store->audit('action.executed', $server['id'], 'success', ['action' => $plan['public']['action'], 'target' => $plan['public']['target']]);
                @unlink($this->store->path('snapshot.' . $server['id'] . '.json'));
                return $result;
            } catch (Throwable $e) {
                $this->store->audit('action.executed', $server['id'], 'failed', ['action' => $plan['public']['action'], 'message' => $e->getMessage()]); throw $e;
            }
        } finally { flock($lock, LOCK_UN); fclose($lock); }
    }
}
