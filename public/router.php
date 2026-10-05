<?php
declare(strict_types=1);
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
if (str_starts_with($path, '/api/')) {
    require dirname(__DIR__) . '/app/api.php';
    return true;
}
if (preg_match('#^/assets/[a-zA-Z0-9_./-]+$#', $path) && !str_contains($path, '..') && is_file(__DIR__ . $path)) return false;
if ($path === '/' || $path === '/index.php') {
    header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    require __DIR__ . '/index.php';
    return true;
}
http_response_code(404); echo 'Not found'; return true;
