<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <meta name="theme-color" content="#111514">
  <title>AWG Control · Центр управления</title>
  <link rel="icon" href="/assets/favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="/assets/styles.css">
</head>
<body>
  <div class="app-shell">
    <aside class="sidebar" id="sidebar">
      <a class="brand" href="#overview" aria-label="AWG Control — обзор"><span class="brand-mark">A<span></span></span><span>AWG<span class="brand-light">CONTROL</span><small>SERVER OPERATIONS</small></span></a>
      <div class="workspace-label">РАБОЧЕЕ ПРОСТРАНСТВО</div>
      <nav id="navigation" aria-label="Основное меню"></nav>
      <div class="sidebar-bottom">
        <div class="connection-card"><span class="connection-led"></span><div><strong id="sidebar-server">Локальная панель</strong><small id="sidebar-status">Подготовка подключения</small></div></div>
        <a class="documentation-link" href="https://docs.amnezia.org/ru/" target="_blank" rel="noreferrer">Документация Amnezia <span>↗</span></a>
        <div class="sidebar-footer"><span class="avatar">OP</span><div><strong>Локальный оператор</strong><small>AWG Control <span class="version">v1.0</span></small></div></div>
      </div>
    </aside>
    <div class="main-shell">
      <header class="topbar">
        <div class="topbar-left"><button class="icon-button mobile-menu" id="menu-toggle" aria-label="Открыть меню"></button><div class="breadcrumb">Рабочее пространство <span>/</span> <strong id="breadcrumb-current">Обзор</strong></div></div>
        <div class="topbar-right"><span class="local-badge"><i></i> LOCAL</span><button class="icon-button" id="refresh-top" title="Обновить данные" aria-label="Обновить данные"></button><button class="icon-button" id="notifications-button" title="Диагностика подключения" aria-label="Диагностика подключения"></button><span class="top-avatar">OP</span></div>
      </header>
      <main id="main" tabindex="-1">
        <div class="page-heading"><div><div class="eyebrow">NETWORK OPERATIONS CENTER</div><h1 id="page-title">Обзор сервера<span class="title-dot">.</span></h1><p id="page-description">Вся инфраструктура. Под вашим контролем.</p></div><div class="heading-actions"><select id="mode-selector" aria-label="Режим данных"><option value="live">Реальный сервер</option><option value="demo">Демонстрация</option></select><button class="button button-primary" id="heading-action"></button></div></div>
        <div class="server-toolbar"><div class="server-select-wrap"><span id="server-icon"></span><select id="server-selector" aria-label="Выберите сервер"></select><span class="server-address" id="server-address">—</span></div><div class="toolbar-state"><span class="pill pill-muted" id="access-badge">ТОЛЬКО ЧТЕНИЕ</span><span class="poll-indicator" id="poll-status"><i></i> Подключение</span><button class="icon-button" id="poll-toggle" title="Приостановить автообновление" aria-label="Приостановить автообновление"></button></div></div>
        <div id="notice-area" aria-live="polite"></div>
        <section id="content" aria-live="polite"><div class="loading-state"><div class="loading-spinner"></div><strong>Подключаем инфраструктуру</strong><span>Состояние сервера, контейнеров и туннелей</span></div></section>
        <footer class="main-footer"><span><span class="footer-dot"></span> AWG CONTROL <span class="footer-separator">/</span> Локальная панель управления</span><span id="last-update">Данные еще не получены</span></footer>
      </main>
    </div>
  </div>
  <div id="toast-region" class="toast-region" role="status" aria-live="polite"></div>
  <dialog id="modal"><div class="modal-content" id="modal-content"></div></dialog>
  <script defer src="/assets/app.bundle.js?v=<?= filemtime(__DIR__ . '/assets/app.bundle.js') ?>"></script>
</body>
</html>
