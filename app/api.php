<?php
declare(strict_types=1);
require_once __DIR__ . '/App.php';
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'");

function response(array $data, int $status = 200): never {
    http_response_code($status); echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

try {
    $remote = $_SERVER['REMOTE_ADDR'] ?? '';
    $host = $_SERVER['HTTP_HOST'] ?? '';
    if (!in_array($remote, ['127.0.0.1', '::1'], true) || !preg_match('/^(127\.0\.0\.1|localhost|\[::1\])(?::[0-9]{1,5})?$/', $host)) throw new ApiError('local_only', 'Приложение доступно только на localhost.', 403);
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin && !in_array($origin, ['http://' . $host, 'https://' . $host], true)) throw new ApiError('invalid_origin', 'Запрос с другого сайта запрещён.', 403);
    if (in_array($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '', ['cross-site'], true)) throw new ApiError('invalid_origin', 'Запрос с другого сайта запрещён.', 403);
    session_name('awg_control');
    ini_set('session.use_strict_mode', '1');
    session_set_cookie_params(['httponly' => true, 'samesite' => 'Strict', 'path' => '/', 'secure' => false]);
    session_start(); $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
    $csrf = $_SESSION['csrf'];
    $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if ($method !== 'GET' && $method !== 'POST') throw new ApiError('method_not_allowed', 'Метод не поддерживается.', 405);
    if ($path !== '/api/bootstrap' && ($_SERVER['HTTP_X_AWG_CLIENT'] ?? '') !== '1') throw new ApiError('client_header_required', 'Отсутствует заголовок локального клиента.', 403);
    if ($method === 'POST' && !hash_equals($csrf, $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '')) throw new ApiError('csrf_invalid', 'Сессия устарела. Обновите приложение.', 403);
    if ((int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > 16000) throw new ApiError('request_too_large', 'Запрос слишком большой.', 413);
    $input = $method === 'POST' ? json_decode(file_get_contents('php://input'), true, 32, JSON_THROW_ON_ERROR) : [];
    if (!is_array($input)) throw new ApiError('invalid_json', 'Ожидается JSON-объект.');
    session_write_close();
    set_time_limit(370);
    $app = new App();
    $server = (string) ($_GET['server'] ?? $_GET['server_id'] ?? '');
    $mode = ($_GET['mode'] ?? 'live') === 'demo' ? 'demo' : 'live';
    $data = null;
    if ($method === 'GET' && $path === '/api/bootstrap') $data = $app->bootstrap();
    elseif ($method === 'GET' && $path === '/api/snapshot') $data = $app->snapshot($server, $mode, ($_GET['force'] ?? '') === '1');
    elseif ($method === 'GET' && $path === '/api/logs') $data = $app->logs($server, $mode, $_GET);
    elseif ($method === 'GET' && $path === '/api/audit') $data = ['entries' => $app->store->auditEntries()];
    elseif ($method === 'GET' && ($path === '/api/config' || $path === '/api/export')) {
        $snapshot = $app->snapshot($server, $mode);
        if ($path === '/api/export') $data = $snapshot;
        else {
            $data = null;
            foreach ($snapshot['tunnels'] ?? [] as $tunnel) if (($tunnel['container'] ?? '') === ($_GET['container'] ?? '') && ($tunnel['interface'] ?? '') === ($_GET['interface'] ?? '')) { $data = $tunnel; break; }
            if ($data === null) throw new ApiError('tunnel_not_found', 'Туннель не найден.', 404);
        }
    }
    elseif ($method === 'POST' && $path === '/api/servers') $data = $app->saveServer($input);
    elseif ($method === 'GET' && preg_match('#^/api/servers/([a-zA-Z0-9_-]+)/fingerprint$#', $path, $match)) $data = $app->fingerprint($match[1]);
    elseif ($method === 'POST' && preg_match('#^/api/servers/([a-zA-Z0-9_-]+)/trust$#', $path, $match)) $data = $app->trust($match[1], (string) ($input['fingerprint'] ?? ''));
    elseif ($method === 'POST' && $path === '/api/actions/plan') $data = $app->plan($input);
    elseif ($method === 'POST' && $path === '/api/actions/execute') $data = $app->execute($input);
    else throw new ApiError('not_found', 'API-метод не найден.', 404);
    response(['ok' => true, 'data' => $data]);
} catch (ApiError $e) { response(['ok' => false, 'error' => ['code' => $e->errorCode, 'message' => $e->getMessage()]], $e->status); }
catch (JsonException $e) { response(['ok' => false, 'error' => ['code' => 'invalid_json', 'message' => 'Некорректный JSON.']], 400); }
catch (Throwable $e) { error_log('AWG Control: ' . $e->getMessage()); response(['ok' => false, 'error' => ['code' => 'internal_error', 'message' => 'Ошибка локального приложения. Проверьте терминал запуска.']], 500); }
