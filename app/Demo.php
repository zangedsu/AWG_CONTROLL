<?php
declare(strict_types=1);

final class Demo
{
    public static function snapshot(): array
    {
        $now = time();
        $clients = [];
        $names = ['MacBook Pro · Алексей', 'iPhone 16', 'Рабочая станция', 'Домашний роутер', 'iPad Air', 'Pixel 9', 'ThinkPad X1', 'Office gateway', 'Android TV', 'Surface Laptop', 'Test device', 'Резервный клиент'];
        foreach ($names as $i => $name) {
            $key = base64_encode(hash('sha256', 'fictional-demo-peer-' . $i, true));
            $online = $i < 8;
            $clients[] = ['id' => 'demo-peer-' . $i, 'public_key' => $key, 'name' => $name, 'allowed_ips' => '10.8.1.' . ($i + 2) . '/32',
                'endpoint' => $online ? '192.0.2.' . ($i + 10) . ':' . (40000 + $i * 123) : '(none)',
                'latest_handshake' => $online ? $now - 15 - $i * 12 : ($i === 11 ? 0 : $now - 10000 * $i),
                'rx_bytes' => (int) (1234567890 * ($i + 1) / 3), 'tx_bytes' => (int) (3456789012 * ($i + 1) / 2),
                'online' => $online, 'container' => 'amnezia-awg2', 'interface' => 'awg0', 'tunnel' => 'awg0', 'created_at' => gmdate('c', $now - 86400 * ($i + 4))];
        }
        $parameters = ['Jc' => '4', 'Jmin' => '40', 'Jmax' => '70', 'S1' => '0', 'S2' => '0', 'H1' => '1547872531', 'H2' => '1789658321', 'H3' => '2135789631', 'H4' => '1875394217'];
        $tunnel = ['container' => 'amnezia-awg2', 'interface' => 'awg0', 'tool' => 'awg', 'public_key' => base64_encode(hash('sha256', 'demo-server', true)),
            'listen_port' => 43829, 'config_path' => '/opt/amnezia/awg/awg0.conf', 'address' => '10.8.1.0/24', 'parameters' => $parameters,
            'config_redacted' => "[Interface]\nPrivateKey = [REDACTED]\nAddress = 10.8.1.0/24\nListenPort = 43829\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 0\nS2 = 0\nH1 = 1547872531\nH2 = 1789658321\nH3 = 2135789631\nH4 = 1875394217\n\n# Демонстрация. Значения не относятся к реальному серверу.\n", 'peers' => $clients];
        $sources = [['id' => 'journal', 'label' => 'Системный журнал', 'type' => 'journal'], ['id' => 'kernel', 'label' => 'Ядро Linux', 'type' => 'journal'],
            ['id' => 'auth', 'label' => 'SSH / авторизация', 'type' => 'file', 'path' => '/var/log/auth.log'], ['id' => 'docker:amnezia-awg2', 'label' => 'amnezia-awg2', 'type' => 'container', 'container' => 'amnezia-awg2'], ['id' => 'syslog', 'label' => 'Syslog', 'type' => 'file', 'path' => '/var/log/syslog']];
        $history = [];
        for ($i = 119; $i >= 0; $i--) {
            $t = $now - $i * 5;
            $history[] = ['timestamp' => $t, 'cpu_percent' => round(18 + 9 * sin($t / 33) + 3 * cos($t / 11), 1), 'memory_percent' => 43.8,
                'rx_bytes' => 83218652160, 'tx_bytes' => 189812345678, 'rx_bps' => 1250000 + 900000 * sin($t / 23) ** 2, 'tx_bps' => 450000 + 750000 * cos($t / 19) ** 2];
        }
        $point = end($history);
        return ['demo' => true, 'collected_at' => gmdate('c'), 'server' => ['id' => 'demo', 'name' => 'Demo · EU Central', 'host' => '192.0.2.24', 'port' => 22, 'username' => 'root', 'read_only' => true, 'protected' => false],
            'host' => ['hostname' => 'awg-eu-01', 'os' => 'Ubuntu 24.04.3 LTS', 'kernel' => '6.8.0-71-generic', 'uptime_seconds' => 1843672,
                'cpu_percent' => $point['cpu_percent'], 'cpu_cores' => 4, 'load' => [0.43, 0.36, 0.29], 'memory' => ['total' => 4294967296, 'available' => 2413779083, 'used' => 1881188213, 'percent' => 43.8],
                'disk' => ['total' => 85899345920, 'used' => 20873541058, 'free' => 65025804862, 'percent' => 24.3],
                'network' => ['rx_bytes' => 83218652160, 'tx_bytes' => 189812345678, 'rx_bps' => $point['rx_bps'], 'tx_bps' => $point['tx_bps'], 'interfaces' => [['name' => 'eth0', 'rx_bytes' => 83218652160, 'tx_bytes' => 189812345678], ['name' => 'docker0', 'rx_bytes' => 318652160, 'tx_bytes' => 912345678]]]],
            'containers' => [
                ['id' => '21ca74ba1d29', 'name' => 'amnezia-awg2', 'image' => 'amnezia-awg2:latest', 'state' => 'running', 'status' => 'Up 21 days', 'health' => 'none', 'created' => '2026-09-12T12:00:00Z', 'ports' => '43829/udp', 'awg' => true, 'mounts' => [], 'log_driver' => 'none', 'stats' => ['cpu_percent' => 8.4, 'memory_usage' => 36700160, 'memory_percent' => 0.85]],
                ['id' => '6fe3abd029c1', 'name' => 'amnezia-dns', 'image' => 'amnezia-dns:latest', 'state' => 'running', 'status' => 'Up 21 days', 'health' => 'none', 'created' => '2026-09-12T12:02:00Z', 'ports' => '53/udp', 'awg' => false, 'mounts' => [], 'stats' => ['cpu_percent' => 0.6, 'memory_usage' => 18874368, 'memory_percent' => 0.44]],
                ['id' => '81f4e6ab02c3', 'name' => 'node-exporter', 'image' => 'prom/node-exporter:v1.9.1', 'state' => 'running', 'status' => 'Up 14 days', 'health' => 'none', 'created' => '2026-09-19T14:00:00Z', 'ports' => '127.0.0.1:9100→9100/tcp', 'awg' => false, 'mounts' => [], 'stats' => ['cpu_percent' => 0.2, 'memory_usage' => 24117248, 'memory_percent' => 0.56]],
                ['id' => 'd30f76902ae8', 'name' => 'watchtower', 'image' => 'containrrr/watchtower:1.7.1', 'state' => 'exited', 'status' => 'Exited (0) 2 days ago', 'health' => 'none', 'created' => '2026-09-15T14:00:00Z', 'ports' => '', 'awg' => false, 'mounts' => [], 'stats' => []]],
            'services' => [['name' => 'docker.service', 'load' => 'loaded', 'active' => 'active', 'sub' => 'running', 'description' => 'Docker Application Container Engine'],
                ['name' => 'containerd.service', 'load' => 'loaded', 'active' => 'active', 'sub' => 'running', 'description' => 'containerd container runtime'],
                ['name' => 'ssh.service', 'load' => 'loaded', 'active' => 'active', 'sub' => 'running', 'description' => 'OpenBSD Secure Shell server'],
                ['name' => 'systemd-journald.service', 'load' => 'loaded', 'active' => 'active', 'sub' => 'running', 'description' => 'Journal Service'],
                ['name' => 'ufw.service', 'load' => 'loaded', 'active' => 'active', 'sub' => 'exited', 'description' => 'Uncomplicated firewall'],
                ['name' => 'cron.service', 'load' => 'loaded', 'active' => 'active', 'sub' => 'running', 'description' => 'Regular background program processing daemon'],
                ['name' => 'nginx.service', 'load' => 'loaded', 'active' => 'inactive', 'sub' => 'dead', 'description' => 'A high performance web server']],
            'clients' => $clients, 'tunnels' => [$tunnel], 'logs' => ['sources' => $sources, 'preview' => self::logs('journal', 6)['text']],
            'network' => ['ports' => "Netid State Local Address:Port Process\nudp UNCONN 0.0.0.0:43829 amnezia-awg\nudp UNCONN 172.29.172.254:53 dnsmasq\ntcp LISTEN 0.0.0.0:22 sshd\ntcp LISTEN 127.0.0.1:9100 node_exporter", 'routes' => "default via 192.0.2.1 dev eth0\n172.29.172.0/24 dev amnezia-dns\n172.17.0.0/16 dev docker0", 'firewall' => "Status: active\n22/tcp ALLOW Anywhere\n43829/udp ALLOW Anywhere"],
            'history' => $history, 'warnings' => ['Демонстрационный режим: все данные на этом экране вымышлены.', 'AWG log-driver=none: журналы контейнера могут быть отключены; используйте системные источники.']];
    }

    public static function logs(string $source, int $limit): array
    {
        $lines = [];
        $messages = ['systemd[1]: Docker service is running', 'sshd[12842]: Accepted publickey for monitor from 192.0.2.10 port 42180 ssh2', 'dockerd[942]: Container amnezia-awg2 health check completed', 'kernel: eth0: link up, 1000 Mbps, full duplex', 'systemd[1]: Finished Daily apt download activities', 'awg0: peer handshake observed (демонстрация)', 'systemd-journald[318]: Journal rotation complete', 'sshd[12904]: Connection closed by authenticating user root 192.0.2.57 [preauth]'];
        for ($i = 0; $i < min($limit, 240); $i++) $lines[] = gmdate('Y-m-d\TH:i:s\Z', time() - (min($limit, 240) - $i) * 7) . ' awg-eu-01 ' . $messages[$i % count($messages)];
        return ['demo' => true, 'source' => $source, 'lines' => $lines, 'text' => implode("\n", $lines), 'collected_at' => gmdate('c')];
    }
}
