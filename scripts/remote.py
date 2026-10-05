#!/usr/bin/env python3
"""Bounded, allowlisted SSH bridge. JSON on stdin/stdout; no external Python packages.

SSH authentication is local, the collector is streamed to python3's stdin. Neither
credentials nor VPN private keys are placed in process arguments. The supplied
production server is permanently read-only, independent of the UI settings.
"""
import base64
import hashlib
import ipaddress
import json
import os
import re
import selectors
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PROTECTED_HOST = '192.0.2.10'
MAX_INPUT = 128 * 1024
MAX_OUTPUT = 4 * 1024 * 1024
OPERATIONS = {'snapshot', 'logs', 'inspect', 'plan', 'execute', 'fingerprint'}


class BridgeError(Exception):
    def __init__(self, message, code='remote_error'):
        super().__init__(message)
        self.code = code


def bounded_process(argv, data=b'', env=None, timeout=60, limit=MAX_OUTPUT):
    """Drain both pipes with a hard aggregate byte limit and a wall-time limit."""
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=env, start_new_session=True)
    selector = selectors.DefaultSelector()
    streams = {'stdout': bytearray(), 'stderr': bytearray()}
    pending = memoryview(data)
    try:
        for pipe, name in ((process.stdout, 'stdout'), (process.stderr, 'stderr')):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        os.set_blocking(process.stdin.fileno(), False)
        if pending:
            selector.register(process.stdin, selectors.EVENT_WRITE, 'stdin')
        else:
            process.stdin.close()
        deadline = time.monotonic() + timeout
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise BridgeError('SSH operation timed out.', 'timeout')
            for key, _ in selector.select(min(0.2, deadline - time.monotonic())):
                pipe, name = key.fileobj, key.data
                if name == 'stdin':
                    try:
                        count = os.write(pipe.fileno(), pending[:16384])
                        pending = pending[count:]
                    except BrokenPipeError:
                        pending = memoryview(b'')
                    if not pending:
                        selector.unregister(pipe)
                        pipe.close()
                else:
                    chunk = os.read(pipe.fileno(), 16384)
                    if not chunk:
                        selector.unregister(pipe)
                        pipe.close()
                    else:
                        streams[name].extend(chunk)
                        if sum(map(len, streams.values())) > limit:
                            raise BridgeError('Remote output exceeded the safe limit.', 'output_limit')
        return process.wait(timeout=2), bytes(streams['stdout']), bytes(streams['stderr'])
    finally:
        selector.close()
        if process.poll() is None:
            # Kill the SSH process group too (including a possible ASKPASS child).
            try:
                import signal
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                process.kill()
            process.wait()
        for pipe in (process.stdin, process.stdout, process.stderr):
            if not pipe.closed:
                pipe.close()


def validate_server(server):
    host = str(server.get('host', '')).strip()
    username = str(server.get('username', '')).strip()
    if not host or len(host) > 253 or not re.fullmatch(r'[a-zA-Z0-9_.:\-]+', host) or host.startswith('-'):
        raise BridgeError('Invalid SSH host.', 'validation')
    if not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_.\-]{0,63}', username):
        raise BridgeError('Invalid SSH username.', 'validation')
    port = int(server.get('port') or 22)
    if not 1 <= port <= 65535:
        raise BridgeError('Invalid SSH port.', 'validation')
    return host, username, port


def protected_server(server):
    host, _, port = validate_server(server)
    if host.lower().rstrip('.') == PROTECTED_HOST:
        return True
    try:
        addresses = {row[4][0] for row in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
        for value in addresses:
            address = ipaddress.ip_address(value)
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            if str(address) == PROTECTED_HOST:
                return True
        return False
    except (OSError, ValueError):
        raise BridgeError('Cannot safely resolve the target before a write.', 'resolve_failed')


def fingerprint(server):
    host, _, port = validate_server(server)
    executable = shutil.which('ssh-keyscan')
    if not executable:
        raise BridgeError('OpenSSH ssh-keyscan is required.', 'missing_dependency')
    code, output, _ = bounded_process([executable, '-T', '6', '-p', str(port), '-t',
                                      'ed25519,ecdsa,rsa', host], timeout=15, limit=32768)
    keys = []
    for line in output.decode('utf-8', 'replace').splitlines():
        if line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) != 3 or not re.fullmatch(r'(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+)', parts[1]):
            continue
        try:
            decoded = base64.b64decode(parts[2], validate=True)
        except ValueError:
            continue
        value = 'SHA256:' + base64.b64encode(hashlib.sha256(decoded).digest()).decode().rstrip('=')
        keys.append({'fingerprint': value, 'key_type': parts[1],
                     'host_key': parts[1] + ' ' + parts[2], 'known_hosts_entry': line})
    if not keys:
        raise BridgeError('Unable to discover an SSH host key.', 'connection_failed')
    preferred = next((key for key in keys if key['key_type'] == 'ssh-ed25519'), keys[0])
    return dict(preferred, keys=keys, pinned=False,
                warning='Key discovery is unauthenticated. Verify the fingerprint before pinning.')


def ssh_call(server, operation, params):
    host, username, port = validate_server(server)
    executable = shutil.which('ssh')
    if not executable:
        raise BridgeError('OpenSSH ssh is required.', 'missing_dependency')
    known_hosts = Path(str(server.get('known_hosts_path', ''))).expanduser()
    if not server.get('known_hosts_path') or not known_hosts.is_file() or known_hosts.stat().st_size == 0:
        raise BridgeError('Pin the SSH host fingerprint before connecting.', 'host_key_required')
    known_hosts_value = str(known_hosts.resolve())
    if any(character in known_hosts_value for character in ('"', '\n', '\r', '\x00')):
        raise BridgeError('Invalid SSH known_hosts path.', 'validation')
    argv = [executable, '-F', '/dev/null', '-T', '-p', str(port), '-l', username,
            '-o', 'ConnectTimeout=8', '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile="' + known_hosts_value + '"',
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'UpdateHostKeys=no',
            '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no', '-o', 'ClearAllForwardings=yes',
            '-o', 'PermitLocalCommand=no', '-o', 'LogLevel=ERROR', '-o', 'NumberOfPasswordPrompts=1']
    environment = os.environ.copy()
    for name in ('SSH_AUTH_SOCK', 'SSH_AGENT_PID', 'AWG_SSH_PASSWORD'):
        environment.pop(name, None)
    request = {'operation': operation, 'params': params, 'host': host,
               'write_allowed': server.get('read_only', True) is False,
               'protected': host == PROTECTED_HOST}
    payload = "REQUEST = " + repr(request) + '\n' + REMOTE_SCRIPT
    with tempfile.TemporaryDirectory(prefix='awg-ssh-') as folder:
        if server.get('password'):
            helper = Path(folder) / 'askpass'
            # The password is in a short-lived environment variable, never the
            # helper file or argv. The helper path contains no credentials.
            helper.write_text('#!/bin/sh\nprintf "%s\\n" "$AWG_SSH_PASSWORD"\n')
            helper.chmod(0o700)
            environment.update(SSH_ASKPASS=str(helper), SSH_ASKPASS_REQUIRE='force',
                               DISPLAY='awg-local:0', AWG_SSH_PASSWORD=str(server['password']))
            argv += ['-o', 'BatchMode=no', '-o', 'PreferredAuthentications=password,keyboard-interactive',
                     '-o', 'PubkeyAuthentication=no']
        else:
            key_path = str(server.get('key_path', ''))
            if not key_path or not Path(key_path).expanduser().is_file():
                raise BridgeError('An SSH password or local private-key path is required.', 'auth_required')
            argv += ['-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-i', str(Path(key_path).expanduser())]
        argv += ['--', host, 'python3 -']
        timeout = 320 if operation == 'execute' and params.get('action') == 'container.update' else 70
        code, output, errors = bounded_process(argv, payload.encode(), environment, timeout=timeout)
    if code != 0:
        diagnostic = errors.decode('utf-8', 'replace')[-1500:]
        diagnostic = diagnostic.replace(str(server.get('password', '\0')), '[redacted]')
        if 'REMOTE HOST IDENTIFICATION HAS CHANGED' in diagnostic or 'Host key verification failed' in diagnostic:
            raise BridgeError('SSH host key differs from the pinned key. Connection rejected.', 'host_key_changed')
        if 'Permission denied' in diagnostic:
            raise BridgeError('SSH authentication failed.', 'auth_failed')
        raise BridgeError('SSH collector failed: ' + diagnostic.strip(), 'connection_failed')
    try:
        result = json.loads(output)
    except (ValueError, UnicodeDecodeError):
        raise BridgeError('Remote host did not return valid collector JSON. Python 3 is required.', 'invalid_response')
    if not isinstance(result, dict):
        raise BridgeError('Invalid remote result.', 'invalid_response')
    return result


# This source runs on the target host without creating a script file. Config
# secrets exist only in that process and are stripped before snapshot output.
REMOTE_SCRIPT = r'''
import base64, collections, concurrent.futures, datetime, fcntl, glob, gzip, hashlib, ipaddress
import json, os, platform, re, selectors, shutil, signal, socket, stat, subprocess, tempfile, time

WARNINGS = []
CONFIG_PATHS = ['/opt/amnezia/awg/awg0.conf', '/opt/amnezia/awg/wg0.conf',
                '/opt/amnezia/wireguard/wg0.conf', '/etc/amnezia/amneziawg/awg0.conf',
                '/etc/amneziawg/awg0.conf', '/etc/wireguard/wg0.conf']
SECRET_FIELDS = {'privatekey', 'presharedkey', 'headerprotectionkey', 'password', 'token', 'secret'}
AWG_PARAMETERS = ['Jc','Jmin','Jmax','S1','S2','S3','S4','H1','H2','H3','H4',
                  'I1','I2','I3','I4','I5','HeaderProtectionKey','ContentPaddingAddition',
                  'RekeyAfterTime','RekeyTimeout','RejectAfterTime','KeepaliveTimeout',
                  'MaxHandshakeAttempts','RandomTrailers','DisableCookies']
AWG3_MARKERS = ['HeaderProtectionKey','ContentPaddingAddition','RekeyAfterTime',
                'RekeyTimeout','RejectAfterTime','KeepaliveTimeout','MaxHandshakeAttempts']

class RemoteError(Exception):
    pass

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def redact(text):
    text = re.sub(r"(?im)(\b[A-Za-z0-9_]*(?:private[ _-]?key|preshared[ _-]?key|headerprotectionkey|password|token|secret|psk)\b[\"']?\s*[=:]\s*)[^\r\n]+", r'\1[redacted]', str(text))
    text = re.sub(r'(?i)(authorization:\s*(?:bearer|basic)\s+)\S+', r'\1[redacted]', text)
    text = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----', '[private key redacted]', text, flags=re.S)
    return text

def run(args, data=None, timeout=8, limit=256*1024):
    process=None;selector=selectors.DefaultSelector()
    try:
        # Commands are allowlisted argument arrays; no user-provided shell.
        process=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        output={'stdout':bytearray(),'stderr':bytearray()};pending=memoryview(data or b'')
        for pipe,name in ((process.stdout,'stdout'),(process.stderr,'stderr')):
            os.set_blocking(pipe.fileno(),False);selector.register(pipe,selectors.EVENT_READ,name)
        os.set_blocking(process.stdin.fileno(),False)
        if pending:selector.register(process.stdin,selectors.EVENT_WRITE,'stdin')
        else:process.stdin.close()
        deadline=time.monotonic()+timeout;truncated=False;failure=None
        while selector.get_map():
            if time.monotonic()>=deadline:failure='Command timed out';break
            for key,_ in selector.select(min(.2,max(0,deadline-time.monotonic()))):
                pipe,name=key.fileobj,key.data
                if name=='stdin':
                    try:count=os.write(pipe.fileno(),pending[:16384]);pending=pending[count:]
                    except BrokenPipeError:pending=memoryview(b'')
                    if not pending:selector.unregister(pipe);pipe.close()
                else:
                    chunk=os.read(pipe.fileno(),16384)
                    if not chunk:selector.unregister(pipe);pipe.close()
                    else:
                        output[name].extend(chunk)
                        if sum(map(len,output.values()))>limit:truncated=True;failure='Output limit reached';break
            if failure:break
        if failure:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            process.wait()
        code=process.wait(timeout=2)
        return {'ok':code==0 and not failure,'code':code,
                'stdout':bytes(output['stdout'][:limit]).decode('utf-8','replace'),
                'stderr':failure or redact(bytes(output['stderr'][:4096]).decode('utf-8','replace')),
                'stderr_all':redact(bytes(output['stderr'][:limit]).decode('utf-8','replace')),
                'truncated':truncated}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'ok': False, 'code': -1, 'stdout': '', 'stderr': type(error).__name__, 'truncated': False}
    finally:
        selector.close()
        if process:
            if process.poll() is None:
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                process.wait()
            for pipe in (process.stdin,process.stdout,process.stderr):
                if not pipe.closed:pipe.close()

def require(result, label):
    if not result['ok']:
        raise RemoteError(label + ': ' + result.get('stderr', 'command failed'))
    return result['stdout']

def readfile(path, limit=512*1024):
    try:
        with open(path, 'rb') as file:
            return file.read(limit).decode('utf-8','replace')
    except OSError:
        return ''

def context_run(container, args, data=None, timeout=8, limit=256*1024):
    return run((['docker','exec','-i',container] if container else []) + args, data, timeout, limit)

def context_tool_available(container,tool):
    if tool not in ('awg','wg'):return False
    if not container:return bool(shutil.which(tool))
    # Check within the existing shell before asking Docker to execute a binary.
    # Missing optional VPN tools otherwise generate noisy OCI errors in dockerd.
    return context_run(container,['sh','-c','command -v "$1" >/dev/null 2>&1','awg-control',tool])['ok']

def context_read(container, path):
    if container:
        result = context_run(container, ['cat', path],limit=512*1024)
        return result['stdout'] if result['ok'] and not result['truncated'] else ''
    try:
        if os.path.getsize(path)>512*1024:return ''
    except OSError:return ''
    return readfile(path)

def mutation_table_read(container,path):
    text=context_read(container,path)
    if text:return text
    if container:
        result=context_run(container,['cat',path],limit=512*1024)
        if result['ok']:return result['stdout']
        if not result['truncated'] and re.search(r'(No such file|not found)',result['stderr'],re.I):return ''
        raise RemoteError('Cannot safely read clientsTable: '+result['stderr'])
    if not os.path.exists(path):return ''
    try:
        if os.path.getsize(path)>512*1024:raise RemoteError('clientsTable exceeds the safe size limit.')
        with open(path,encoding='utf-8') as file:return file.read(512*1024)
    except OSError as error:raise RemoteError('Cannot safely read clientsTable: '+type(error).__name__)

def parse_config(text):
    interface, peers, section = {}, [], None
    name = ''
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith('#'):
            name = stripped.lstrip('#').strip()[:128]
            continue
        if stripped.lower() == '[interface]':
            section = interface
        elif stripped.lower() == '[peer]':
            section = {'name':name} if name else {}
            peers.append(section)
            name = ''
        elif section is not None and '=' in stripped and not stripped.startswith(';'):
            key, value = stripped.split('=',1)
            section[key.strip()] = value.strip().split(' #',1)[0].strip()
    return interface, peers

def infer_protocol_version(config):
    # Mirror hasAwg3Markers/awgVersionOf in the official awgProtocolConfig.cpp.
    # This is a configuration inference, not a claim about installed binaries.
    value=lambda key:str(config.get(key) or '').strip()
    if any(value(key) for key in AWG3_MARKERS) or any(
            value(key) and value(key).lower()!='off' for key in ('RandomTrailers','DisableCookies')):
        return '3.1'
    if any(value(key) for key in ('S3','S4')) or any('-' in value(key) for key in ('H1','H2','H3','H4')):
        return '2.0'
    if any(value(key) for key in ('I1','I2','I3','I4','I5')):return '1.5'
    if any(value(key) for key in ('Jc','Jmin','Jmax','S1','S2','H1','H2','H3','H4')):return '1.0'
    return 'WireGuard'

def client_cps_parameters(text,config):
    # Official configure_container.sh retains client-only CPS as # I1..I5 in
    # [Interface]. Only those five comment keys may supplement a client export;
    # comments never become active server configuration. They can identify the
    # client protocol metadata used by the original Amnezia installation.
    parameters={};in_interface=False
    for line in text.splitlines():
        stripped=line.strip()
        if stripped.startswith('['):in_interface=stripped.lower()=='[interface]'
        if not in_interface:continue
        match=re.fullmatch(r'#\s*(I[1-5])\s*=\s*(.+)',stripped)
        if match:
            key,value=match.groups();value=value.split(' #',1)[0].strip()
            if value and not str(config.get(key) or '').strip():parameters[key]=value
    return parameters

def client_keepalive(params,config):
    awg3=infer_protocol_version(config)=='3.1'
    raw=params.get('keepalive','25-35' if awg3 else '25')
    if isinstance(raw,bool) or not isinstance(raw,(str,int)):
        raise RemoteError('Persistent keepalive must be an integer or an AWG 3.1 range.')
    value=str(raw).strip()
    if not re.fullmatch(r'[0-9]{1,5}(?:-[0-9]{1,5})?',value):
        raise RemoteError('Persistent keepalive must be 0..65535 or a valid AWG 3.1 range N-M.')
    parts=[int(part) for part in value.split('-')]
    if any(part>65535 for part in parts) or (len(parts)==2 and parts[0]>parts[1]):
        raise RemoteError('Persistent keepalive range requires 0 <= N <= M <= 65535.')
    if len(parts)==2 and not awg3:
        raise RemoteError('Persistent keepalive ranges require AmneziaWG 3.1 configuration markers.')
    return '-'.join(str(part) for part in parts)

def table_names(table):
    names = {}
    if isinstance(table, dict):
        for key,entry in table.items():
            if isinstance(entry,str):names[str(key)]=entry[:128]
            elif isinstance(entry,dict):
                userdata=entry.get('userData') if isinstance(entry.get('userData'),dict) else {}
                names[str(entry.get('clientId') or key)]=str(userdata.get('clientName') or entry.get('clientName') or entry.get('name') or '')[:128]
        return names
    if not isinstance(table, list):
        return names
    for entry in table:
        if not isinstance(entry, dict):
            continue
        key = entry.get('clientId') or entry.get('publicKey') or entry.get('PublicKey')
        userdata = entry.get('userData') if isinstance(entry.get('userData'),dict) else {}
        if key:
            names[key] = str(userdata.get('clientName') or entry.get('name') or '')[:128]
    return names

def json_value(text, default):
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return default

def intvalue(value):
    try: return int(value)
    except (ValueError, TypeError): return 0

def host_info():
    mem = {}
    for line in readfile('/proc/meminfo').splitlines():
        key, value = line.split(':',1)
        mem[key] = intvalue(value.strip().split()[0])*1024
    total, available = mem.get('MemTotal',0), mem.get('MemAvailable',mem.get('MemFree',0))
    def cpu():
        values = [intvalue(v) for v in readfile('/proc/stat').splitlines()[0].split()[1:]]
        return sum(values), sum(values[3:5])
    try:
        a,b=cpu(); time.sleep(0.18); c,d=cpu()
        percentage = round(100 * (1 - (d-b)/max(1,c-a)),1)
    except (IndexError,OSError): percentage = None
    interfaces = []
    for line in readfile('/proc/net/dev').splitlines()[2:]:
        if ':' in line:
            name,values=line.split(':',1); fields=values.split()
            if len(fields)>=9: interfaces.append({'name':name.strip(),'rx_bytes':intvalue(fields[0]),'tx_bytes':intvalue(fields[8])})
    disk = shutil.disk_usage('/')
    osrelease = {}
    for line in readfile('/etc/os-release').splitlines():
        if '=' in line:
            key,value=line.split('=',1); osrelease[key]=value.strip('"')
    ipresult=run(['ip','-j','address','show'])
    for device in json_value(ipresult['stdout'],[]):
        for entry in interfaces:
            if entry['name'] == device.get('ifname'):
                entry['addresses']=[a.get('local') for a in device.get('addr_info',[])]
                entry['state']=device.get('operstate')
    default_routes=json_value(run(['ip','-j','route','show','default'])['stdout'],[])
    uplinks={route.get('dev') for route in default_routes if route.get('dev')}
    transport=[item for item in interfaces if item['name'] in uplinks]
    if not transport:
        transport=[item for item in interfaces if not re.match(r'^(lo|veth|docker|br-|amn|awg|wg|tun|tap)',item['name'])
                   and not os.path.exists('/sys/class/net/'+item['name']+'/bridge')
                   and not os.path.exists('/sys/class/net/'+item['name']+'/tun_flags')]
    return {'hostname':socket.gethostname(),'os':osrelease.get('PRETTY_NAME',platform.system()),
            'kernel':platform.release(),'uptime_seconds':float(readfile('/proc/uptime').split()[0] or 0),
            'cpu_percent':percentage,'cpu_cores':os.cpu_count(),'load':list(os.getloadavg()),
            'memory':{'total':total,'available':available,'used':total-available,'percent':round((total-available)*100/max(1,total),1)},
            'disk':{'total':disk.total,'used':disk.used,'free':disk.free,'percent':round(disk.used*100/max(1,disk.total),1)},
            'network':{'interfaces':interfaces,'rx_bytes':sum(i['rx_bytes'] for i in transport),
                       'tx_bytes':sum(i['tx_bytes'] for i in transport),'aggregate_interfaces':[i['name'] for i in transport],
                       'aggregate_note':'Default-route uplink interface totals; per-interface counters are also available.'}}

def percentage(value):
    try:return float(str(value or '0').strip().rstrip('%'))
    except ValueError:return 0.0

def bytevalue(value):
    match=re.fullmatch(r'\s*([0-9.]+)\s*([KMGTPE]?i?B)\s*',str(value),re.I)
    if not match:return 0
    suffix=match.group(2).upper();unit=suffix[0];exponent='BKMGTPE'.index(unit)
    return int(float(match.group(1))*(1024 if 'I' in suffix else 1000)**exponent)

def normalize_stats(item):
    usage=str(item.get('MemUsage') or '')
    used,total=(usage.split('/',1)+[''])[:2] if '/' in usage else (usage,'')
    return {'cpu_percent':percentage(item.get('CPUPerc')),'memory_usage':usage,
            'memory_percent':percentage(item.get('MemPerc')),'memory_bytes':bytevalue(used),
            'memory_limit':bytevalue(total),'network_io':item.get('NetIO'),'block_io':item.get('BlockIO'),
            'pids':intvalue(item.get('PIDs'))}

def docker_objects():
    listing=run(['docker','ps','-a','--format','{{json .}}'], timeout=10)
    if not listing['ok']:
        WARNINGS.append('Docker unavailable or access denied: '+listing['stderr'])
        return [],[]
    ids=[json_value(line,{}).get('ID') for line in listing['stdout'].splitlines()][:80]
    ids=[identifier for identifier in ids if identifier]
    if not ids: return [],[]
    details=run(['docker','inspect']+ids,timeout=10,limit=1024*1024)
    if details['truncated']:
        WARNINGS.append('Docker inspect exceeds collector limit.')
    raw=json_value(details['stdout'],[])
    stats=run(['docker','stats','--no-stream','--format','{{json .}}'],timeout=10)
    statmap={s.get('ID'):s for s in (json_value(line,{}) for line in stats['stdout'].splitlines())}
    containers=[]
    for entry in raw:
        config,state,network=entry.get('Config',{}),entry.get('State',{}),entry.get('NetworkSettings',{})
        identifier=entry.get('Id',''); name=entry.get('Name','').lstrip('/')
        mounts=[{'type':m.get('Type'),'source':m.get('Source'),'destination':m.get('Destination'),'read_only':not m.get('RW',False)} for m in entry.get('Mounts',[])]
        # Never return environment variables, command arguments, raw labels,
        # or inspection data containing embedded credentials.
        containers.append({'id':identifier[:12],'name':name,'image':config.get('Image'),
            'image_id':entry.get('Image','')[:19],'status':state.get('Status'),'state':state.get('Status'),
            'health':state.get('Health',{}).get('Status'),'created':entry.get('Created'),
            'started_at':state.get('StartedAt'),'restart_count':entry.get('RestartCount',0),
            'ports':network.get('Ports',{}),'mounts':mounts,
            'stats':normalize_stats(statmap.get(identifier[:12],{})),'logging_driver':entry.get('HostConfig',{}).get('LogConfig',{}).get('Type'),
            'restart_policy':entry.get('HostConfig',{}).get('RestartPolicy',{}).get('Name'),
            'networks':list(network.get('Networks',{})),
            'awg':bool(re.search(r'(awg|wireguard)',name+' '+str(config.get('Image') or ''),re.I)),
            'amnezia':bool(re.search(r'amnezia',name+' '+str(config.get('Image') or ''),re.I))})
    return containers,raw

def discover_tunnels(containers):
    contexts=[None]+[c['name'] for c in containers if c['awg'] and c['state']=='running']
    tunnels=[]
    for container in contexts[:12]:
        selected=None
        for tool in ('awg','wg'):
            if not context_tool_available(container,tool):continue
            result=context_run(container,[tool,'show','interfaces'])
            if result['ok'] and result['stdout'].split():
                selected=(tool,result['stdout'].split()); break
        if not selected: continue
        tool,interfaces=selected
        for iface in interfaces[:12]:
            if not re.fullmatch(r'[A-Za-z0-9_.\-]{1,32}',iface): continue
            paths=CONFIG_PATHS + ['/etc/amneziawg/'+iface+'.conf','/etc/wireguard/'+iface+'.conf']
            # Prefer configuration named after the running interface.
            paths=sorted(p for p in set(paths) if os.path.basename(p)==iface+'.conf')
            path,text=None,''
            for candidate in paths:
                content=context_read(container,candidate)
                if content and '[Interface]' in content:
                    path,text=candidate,content;break
            config,cfgpeers=parse_config(text)
            table=json_value(context_read(container,os.path.dirname(path)+'/clientsTable'),[]) if path else []
            names=table_names(table)
            fields={}
            # Do not use `show ... dump` or showconf: both expose secret keys.
            for field in ('peers','public-key','listen-port','latest-handshakes','transfer','endpoints','allowed-ips'):
                fields[field]=context_run(container,[tool,'show',iface,field])
            peers={}
            for line in fields['peers']['stdout'].splitlines():
                key=line.strip()
                if key: peers[key]={'public_key':key,'name':names.get(key,''),'allowed_ips':'','endpoint':'','latest_handshake':0,'rx_bytes':0,'tx_bytes':0}
            for item in cfgpeers:
                key=item.get('PublicKey')
                if not key: continue
                peer=peers.setdefault(key,{'public_key':key,'latest_handshake':0,'rx_bytes':0,'tx_bytes':0,'endpoint':''})
                peer['name']=names.get(key) or item.get('name','')
                peer['allowed_ips']=item.get('AllowedIPs','')
                peer['configured']=True
            for field in ('latest-handshakes','transfer','endpoints','allowed-ips'):
                for line in fields[field]['stdout'].splitlines():
                    parts=line.split('\t')
                    if len(parts)<2: continue
                    key=parts[0]
                    peer=peers.setdefault(key,{'public_key':key,'name':names.get(key,''),'latest_handshake':0,'rx_bytes':0,'tx_bytes':0})
                    if field=='latest-handshakes': peer['latest_handshake']=intvalue(parts[1])
                    elif field=='transfer' and len(parts)>=3: peer.update(rx_bytes=intvalue(parts[1]),tx_bytes=intvalue(parts[2]))
                    elif field=='endpoints': peer['endpoint']='' if parts[1]=='(none)' else parts[1]
                    else: peer['allowed_ips']=parts[1]
            for peer in peers.values():
                peer['online']=bool(peer.get('latest_handshake') and 0<=time.time()-peer['latest_handshake']<180)
                peer['name']=peer.get('name') or 'Клиент '+peer['public_key'][:8]
                peer['persistent_keepalive']=next((p.get('PersistentKeepalive') for p in cfgpeers if p.get('PublicKey')==peer['public_key']),None)
            parameters={k:v for k,v in config.items() if k in AWG_PARAMETERS and k.lower() not in SECRET_FIELDS}
            version=infer_protocol_version(dict(config,**client_cps_parameters(text,config)))
            tunnels.append({'container':container,'interface':iface,'tool':tool,
                'protocol':'WireGuard' if version=='WireGuard' else 'AmneziaWG',
                'protocol_version':version,'version_inferred':True,
                'public_key':fields['public-key']['stdout'].strip(),'server_pubkey':fields['public-key']['stdout'].strip(),
                'listen_port':intvalue(fields['listen-port']['stdout'].strip()),'config_path':path,
                'address':config.get('Address',''),'parameters':parameters,'config_redacted':redact(text),
                'peers':list(peers.values()),'peer_count':len(peers),'clients_table_available':bool(table),
                'status':'running','capabilities':{'read':True,'manage_clients':bool(path),
                   'export_existing_private_keys':False},
                'errors':[{ 'source':k,'message':v['stderr']} for k,v in fields.items() if not v['ok']]})
    return tunnels

def discover_host_log_files():
    files=[];eligible_count=0
    for directory,subdirs,names in os.walk('/var/log',followlinks=False):
        depth=len(os.path.relpath(directory,'/var/log').split(os.sep)) if directory!='/var/log' else 0
        subdirs[:]=sorted(name for name in subdirs if depth<3 and not os.path.islink(os.path.join(directory,name)))
        for name in sorted(names):
            # Include rotations and gzip archives of text logs. Binary login
            # accounting, journal files and databases have dedicated tools.
            if not (re.search(r'\.log(?:\.[0-9]+)?(?:\.gz)?$',name) or
                    re.fullmatch(r'(?:syslog|messages|auth|kern|daemon|debug|dmesg|ufw)(?:\.[0-9]+)?(?:\.gz)?',name)):
                continue
            path=os.path.join(directory,name)
            try:
                if not stat.S_ISREG(os.lstat(path).st_mode):continue
            except OSError:continue
            if not os.path.realpath(path).startswith('/var/log/'):continue
            eligible_count+=1
            if len(files)<120:files.append(path)
    return files,eligible_count

def discover_logs(containers,services):
    sources=[]
    for identifier,label,args in [('journal','Системный журнал',['journalctl','-n','1','--no-pager']),
        ('kernel','Ядро',['journalctl','-k','-n','1','--no-pager']),
        ('auth','SSH / аутентификация',['journalctl','-u','ssh','-u','sshd','-n','1','--no-pager'])]:
        result=run(args)
        sources.append({'id':identifier,'label':label,'type':'journal','available':result['ok'],
                        'error':None if result['ok'] else result['stderr']})
    files,totalfiles=discover_host_log_files()
    if totalfiles>len(files):WARNINGS.append('Log discovery limited to 120 text files; '+str(totalfiles)+' available.')
    for path in files:
        readable=os.access(path,os.R_OK)
        sources.append({'id':'file:'+path,'label':path,'type':'file','path':path,'available':readable,
                        'compressed':path.endswith('.gz'),'error':None if readable else 'Permission denied'})
    for item in containers:
        driver=item.get('logging_driver')
        sources.append({'id':'container:'+item['name'],'label':'Docker · '+item['name'],
            'type':'container','container':item['name'],'available':driver not in ('none',None),
            'error':'Docker logging driver is none; historical container logs do not exist.' if driver=='none' else None})
        if (item['awg'] or item.get('amnezia')) and item['state']=='running':
            discovered=context_run(item['name'],['find','/var/log','/opt/amnezia','-maxdepth','3','-type','f','-name','*.log'],timeout=5)
            for path in discovered['stdout'].splitlines()[:15]:
                if re.fullmatch(r'/(?:var/log|opt/amnezia)/[A-Za-z0-9_/.-]+\.log',path):
                    sources.append({'id':'containerfile:'+item['name']+':'+path,'label':item['name']+' · '+path,
                                    'type':'containerfile','container':item['name'],'path':path,'available':True})
    for service in services:
        if re.search(r'(docker|awg|wireguard|amnezia|ssh|nginx|xray)',service['name'],re.I):
            sources.append({'id':'service:'+service['name'],'label':'Служба · '+service['name'],
                            'type':'service','service':service['name'],'available':True})
    return sources

def services_info():
    result=run(['systemctl','list-units','--type=service','--all','--no-pager','--no-legend','--plain'],timeout=8)
    services=[]
    for line in result['stdout'].splitlines()[:250]:
        fields=line.strip().lstrip('●').strip().split(None,4)
        if len(fields)>=4 and fields[0].endswith('.service'):
            services.append({'name':fields[0],'load':fields[1],'active':fields[2],'sub':fields[3],'description':fields[4] if len(fields)>4 else ''})
    if not result['ok']: WARNINGS.append('systemd is unavailable: '+result['stderr'])
    return services

def collect_snapshot():
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        hostfuture=pool.submit(host_info); dockerfuture=pool.submit(docker_objects); servicefuture=pool.submit(services_info)
        netfuture=pool.submit(lambda:{'ports':run(['ss','-tunlp']),'routes':run(['ip','route','show']),
            'firewall':run(['iptables','-S']),'firewall6':run(['ip6tables','-S']),
            'nftables':run(['nft','list','ruleset'],limit=128*1024)})
        host=hostfuture.result(); containers,raw=dockerfuture.result();services=servicefuture.result();net=netfuture.result()
    tunnels=discover_tunnels(containers)
    clients=[]
    for tunnel in tunnels:
        for peer in tunnel['peers']:
            clients.append(dict(peer,container=tunnel['container'],interface=tunnel['interface'],
                                config_path=tunnel['config_path'],tool=tunnel['tool'],
                                id=(tunnel['container'] or 'host')+':'+tunnel['interface']+':'+peer['public_key']))
    preview=run(['journalctl','--no-pager','-n','6','-o','short-iso'])
    return {'collected_at':now(),'host':host,'containers':containers,'services':services,
            'tunnels':tunnels,'clients':clients,'logs':{'sources':discover_logs(containers,services),'preview':redact(preview['stdout']) if preview['ok'] else ''},
            'network':{k:redact(v['stdout']) for k,v in net.items()},
            'network_status':{k:{'available':v['ok'],'error':None if v['ok'] else v['stderr'],'truncated':v['truncated']} for k,v in net.items()},
            'warnings':WARNINGS,'collector_version':'1.0','protected':REQUEST.get('protected',False)}

def log_output(params):
    source=str(params.get('source') or 'journal')
    lines=max(10,min(2000,intvalue(params.get('lines') or 200)))
    since=str(params.get('since') or '')
    if since and not re.fullmatch(r'[0-9A-Za-z :+.,T_\-]{1,50}',since): raise RemoteError('Invalid log timestamp.')
    journal=['journalctl','--no-pager','-o','short-iso','-n',str(lines)]
    if since: journal+=['--since',since]
    priority=str(params.get('priority') or '')
    if priority:
        if priority not in ('0','1','2','3','4','5','6','7','emerg','alert','crit','err','warning','notice','info','debug'):
            raise RemoteError('Invalid journal priority.')
        journal+=['--priority',priority]
    warning=None
    if source=='journal': result=run(journal,limit=512*1024)
    elif source=='kernel': result=run(journal+['-k'],limit=512*1024)
    elif source=='auth': result=run(journal+['-u','ssh','-u','sshd'],limit=512*1024)
    elif source.startswith('service:'):
        name=source[8:]
        if not re.fullmatch(r'[A-Za-z0-9_@.\-]{1,128}\.service',name): raise RemoteError('Invalid service.')
        result=run(journal+['-u',name],limit=512*1024)
    elif source.startswith('container:'):
        name=source[10:]; validate_container(name)
        info=json_value(require(run(['docker','inspect',name]),'Docker inspect'),[])
        if not info: raise RemoteError('Container does not exist.')
        if info[0].get('HostConfig',{}).get('LogConfig',{}).get('Type')=='none':
            return {'source':source,'available':False,'text':'Контейнер использует logging driver none. Docker не сохраняет его логи.','lines':0,'collected_at':now(),'truncated':False}
        args=['docker','logs','--timestamps','--tail',str(lines)]
        if since: args+=['--since',since]
        result=run(args+[name],limit=512*1024)
        result['stdout']+=result.get('stderr_all',result['stderr']) if result['ok'] else ''
    elif source.startswith('file:'):
        path=source[5:]
        files,_=discover_host_log_files()
        if path not in files: raise RemoteError('Only discovered regular /var/log text files are readable.')
        if path.endswith('.gz'):
            chunks=collections.deque(maxlen=lines);readbytes=0;truncated=False
            try:
                with gzip.open(path,'rb') as archive:
                    while readbytes<4*1024*1024:
                        line=archive.readline(min(256*1024,4*1024*1024-readbytes))
                        if not line:break
                        readbytes+=len(line);chunks.append(line)
                    if readbytes>=4*1024*1024:truncated=True
                result={'ok':True,'stdout':b''.join(chunks).decode('utf-8','replace')[-512*1024:],'stderr':'','truncated':truncated}
                if truncated:warning='Archive read limited to the first 4 MiB of decompressed text; the latest end may not be reached.'
            except (OSError,EOFError):result={'ok':False,'stdout':'','stderr':'Unreadable gzip archive.','truncated':False}
        else:result=run(['tail','-n',str(lines),'--',path],limit=512*1024)
        if since or priority:warning='Timestamp and priority filters apply to journal sources; text files use line tail and search only.'
    elif source.startswith('containerfile:'):
        name,path=source[14:].split(':',1);validate_container(name)
        if not re.fullmatch(r'/(?:var/log|opt/amnezia)/[A-Za-z0-9_/.-]+\.log',path) or '..' in path: raise RemoteError('Invalid log path.')
        result=context_run(name,['tail','-n',str(lines),path],limit=512*1024)
    else: raise RemoteError('Unknown log source.')
    text=redact(result['stdout'])
    search=str(params.get('search') or '')[:128]
    if search: text='\n'.join(line for line in text.splitlines() if search.casefold() in line.casefold())
    return {'source':source,'available':result['ok'],'text':text,'lines':len(text.splitlines()),
            'collected_at':now(),'error':None if result['ok'] else result['stderr'],'truncated':result['truncated'],'warning':warning}

def validate_container(name):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}',str(name)):
        raise RemoteError('Invalid container name.')

def validate_interface(name):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.\-]{0,31}',str(name)):
        raise RemoteError('Invalid tunnel interface.')

def validate_key(key):
    try:
        if len(base64.b64decode(str(key),validate=True))!=32: raise ValueError()
    except ValueError: raise RemoteError('Invalid peer public key.')

def selected_tunnel(params):
    container=params.get('container') or None
    if container: validate_container(container)
    iface=str(params.get('interface') or '');validate_interface(iface)
    path=str(params.get('config_path') or '')
    allowed=CONFIG_PATHS + ['/etc/amneziawg/'+iface+'.conf','/etc/wireguard/'+iface+'.conf']
    if path not in allowed or os.path.basename(path)!=iface+'.conf': raise RemoteError('Unsupported configuration path for this interface.')
    text=context_read(container,path)
    if not text or '[Interface]' not in text: raise RemoteError('Tunnel configuration is unreadable.')
    tool=None
    for candidate in ('awg','wg'):
        if not context_tool_available(container,candidate):continue
        result=context_run(container,[candidate,'show','interfaces'])
        if result['ok'] and iface in result['stdout'].split(): tool=candidate;break
    if tool is None: raise RemoteError('The selected tunnel must be running before modifying clients.')
    config,peers=parse_config(text)
    return container,iface,path,tool,text,config,peers

def compose_context(info,params):
    name=info.get('Name','').lstrip('/')
    if re.search(r'(amnezia|awg|wireguard)',name,re.I):
        raise RemoteError('Amnezia containers require the official protocol migration workflow; generic image replacement is disabled.')
    labels=info.get('Config',{}).get('Labels') or {}
    project=str(labels.get('com.docker.compose.project') or '')
    service=str(labels.get('com.docker.compose.service') or '')
    directory=str(labels.get('com.docker.compose.project.working_dir') or '')
    files=str(labels.get('com.docker.compose.project.config_files') or '')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_\-]{0,99}',project) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_\-]{0,99}',service):
        raise RemoteError('Only containers with valid Docker Compose project/service labels can be updated.')
    if not directory.startswith('/') or not os.path.isdir(directory) or not files:
        raise RemoteError('The original Compose working directory and config files must exist.')
    directory=os.path.realpath(directory)
    paths=[]
    for item in files.split(','):
        path=os.path.realpath(item if item.startswith('/') else os.path.join(directory,item))
        if not path.startswith(directory.rstrip('/')+'/') or not os.path.isfile(path) or not path.endswith(('.yml','.yaml')):
            raise RemoteError('Compose configuration must be existing YAML inside its declared project directory.')
        paths.append(path)
    if not 1<=len(paths)<=8:raise RemoteError('Unsupported number of Compose config files.')
    desired=params.get('image')
    current=info.get('Config',{}).get('Image')
    if desired and desired!=current:
        raise RemoteError('Update follows the existing Compose image declaration; edit the Compose file to change its image reference.')
    base=['docker','compose','--project-name',project,'--project-directory',directory]
    for path in paths:base+=['-f',path]
    if not run(['docker','compose','version'])['ok']:raise RemoteError('Docker Compose v2 is required for managed updates.')
    declared=require(run(base+['config','--services'],timeout=15),'Validate Compose configuration').splitlines()
    if service not in declared:raise RemoteError('Container service is absent from its current Compose configuration.')
    resolved=json_value(require(run(base+['config','--format','json'],timeout=15,limit=1024*1024),'Resolve Compose configuration'),None)
    if not isinstance(resolved,dict) or not isinstance(resolved.get('services',{}).get(service),dict):
        raise RemoteError('Compose must provide a valid resolved JSON service configuration.')
    image=resolved['services'][service].get('image')
    if not isinstance(image,str) or not image or resolved['services'][service].get('build'):
        raise RemoteError('Only Compose services using a declared image without a build step can be updated.')
    digests=[]
    for path in paths:
        if os.path.getsize(path)>4*1024*1024:raise RemoteError('Compose file exceeds the safe 4 MiB limit.')
        digests.append(hashlib.sha256(readfile(path,4*1024*1024).encode()).hexdigest())
    precondition=hashlib.sha256(json.dumps({'config':resolved,'files':digests},sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return {'base':base,'project':project,'service':service,'directory':directory,'files':paths,
            'image':image,'previous_image':current,'precondition':precondition}

def plan_action(params):
    action=str(params.get('action') or '')
    summaries={'client.create':'Создать клиента и сохранить его публичный ключ на сервере.',
      'client.delete':'Удалить peer из работающего интерфейса, конфигурации и clientsTable.',
      'client.rename':'Обновить имя клиента в clientsTable.',
      'container.restart':'Перезапустить Docker-контейнер.', 'container.start':'Запустить Docker-контейнер.',
      'container.stop':'Остановить Docker-контейнер.',
      'container.update':'Загрузить образ и пересоздать контейнер с резервной копией и откатом.',
      'service.restart':'Перезапустить службу systemd.', 'service.start':'Запустить службу systemd.',
      'service.stop':'Остановить службу systemd.', 'host.reboot':'Перезагрузить сервер.'}
    if action not in summaries: raise RemoteError('Unknown allowlisted action.')
    warnings=[];commands=[];target='server';executable=bool(REQUEST.get('write_allowed')) and not REQUEST.get('protected')
    state={'action':action};extra={}
    if action.startswith('client.'):
        container,iface,path,tool,text,config,peers=selected_tunnel(params)
        target=(container or 'host')+'/'+iface
        if action!='client.create':
            validate_key(params.get('public_key'))
            if not any(peer.get('PublicKey')==params['public_key'] for peer in peers): raise RemoteError('Peer is absent from persistent configuration.')
        if action in ('client.create','client.rename'):
            name=str(params.get('name') or '').strip()
            if not name or len(name)>100 or any(ord(c)<32 for c in name): raise RemoteError('Client name must contain 1–100 visible characters.')
        if action=='client.create':
            for value in str(params.get('dns') or '1.1.1.1, 1.0.0.1').split(','): ipaddress.ip_address(value.strip())
            for value in str(params.get('allowed_ips') or '0.0.0.0/0').split(','): ipaddress.ip_network(value.strip(),strict=False)
            client_keepalive(params,config)
        if str(config.get('SaveConfig','')).lower()=='true':
            raise RemoteError('SaveConfig=true can overwrite client edits; this configuration is unsupported for mutations.')
        runtime=require(context_run(container,[tool,'show',iface,'peers']),'Read current tunnel peers')
        state.update(container=container,interface=iface,config=text,
            table=context_read(container,os.path.dirname(path)+'/clientsTable'),runtime_peers=sorted(runtime.splitlines()))
        commands=['Read current configuration and clientsTable; acquire exclusive lock.',
                  'Create timestamped backups with mode 0600.',
                  'Write configuration atomically, synchronize '+tool+' without tunnel restart.',
                  'Restore backups on failure.']
        warnings=['Для нового клиента приватный ключ выдаётся один раз в .conf. Приватные ключи существующих клиентов восстановить нельзя.']
    elif action.startswith('container.'):
        target=str(params.get('container') or '');validate_container(target)
        info=json_value(require(run(['docker','inspect',target]),'Inspect container'),[])
        if not info: raise RemoteError('Container does not exist.')
        state.update(container_id=info[0].get('Id'),image_id=info[0].get('Image'),
            config=info[0].get('Config'),host_config=info[0].get('HostConfig'),
            status=info[0].get('State',{}).get('Status'),restart_count=info[0].get('RestartCount'))
        if action=='container.update':
            try:
                compose=compose_context(info[0],params)
                state['compose_precondition']=compose['precondition']
                extra.update(image=compose['image'],previous_image=compose['previous_image'],service=compose['service'],project=compose['project'])
                commands=['Save root-only inspect and Compose file backups; docker commit the previous filesystem.',
                          ' '.join(compose['base']+['pull',compose['service']]),
                          ' '.join(compose['base']+['up','-d','--no-deps',compose['service']]),
                          'Check running/health status; automatically restore the backup image if deployment fails.']
                warnings=['Обновление использует текущую декларацию Docker Compose и временно прерывает работу контейнера.',
                          'docker commit кратко приостанавливает контейнер. Тома сохраняются; их данные не входят в резервную копию и миграции данных не откатываются.']
            except RemoteError as error:
                executable=False;commands=['Review the official Amnezia migration workflow or manage the container through Docker Compose.']
                warnings=[str(error),'Обновление образа не является миграцией версии протокола AWG.']
        else:
            commands=['docker '+action.split('.')[1]+' '+target]
            warnings=['Соединения клиентов этого контейнера могут прерваться.']
    elif action.startswith('service.'):
        target=str(params.get('service') or '')
        if not re.fullmatch(r'[A-Za-z0-9_@.\-]{1,128}\.service',target): raise RemoteError('Invalid service unit.')
        if not run(['systemctl','show',target,'--property=LoadState','--value'])['stdout'].strip()=='loaded': raise RemoteError('Service is not loaded.')
        state['unit']=target
        state['state']=require(run(['systemctl','show',target,'--property=LoadState','--property=ActiveState','--property=SubState','--value']),'Read service state')
        commands=['systemctl '+action.split('.')[1]+' '+target];warnings=['Действие изменит доступность службы.']
    else:
        state['machine_id']=readfile('/etc/machine-id').strip()
        state['boot_id']=readfile('/proc/sys/kernel/random/boot_id').strip()
        commands=['systemctl reboot'];warnings=['SSH, VPN и все службы будут временно недоступны.']
    if REQUEST.get('protected'): warnings.append('Этот реальный сервер навсегда защищён от изменений в приложении.')
    elif not REQUEST.get('write_allowed'): warnings.append('Для сервера включён режим только чтения.')
    digest=hashlib.sha256(json.dumps(state,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return dict({'action':action,'target':target,'summary':summaries[action],'commands':commands,
                 'warnings':warnings,'executable':executable,'precondition':digest},**extra)

def backup_file(container,path,token):
    backup=path+'.awg-control-'+token+'.bak'
    if container:
        require(context_run(container,['sh','-c','umask 077; cp "$1" "$2" && chmod 600 "$2"','awg-control',path,backup]),'Create backup')
    else:
        fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(fd,'wb') as file: file.write(context_read(None,path).encode())
    return backup

def write_atomic(container,path,text,token):
    temp=path+'.awg-control-'+token+'.tmp'
    if container:
        result=context_run(container,['sh','-c','umask 077; cat > "$2" && chmod 600 "$2" && mv -f "$2" "$1"','awg-control',path,temp],text.encode())
        require(result,'Atomic configuration write')
    else:
        fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(fd,'wb') as file:
            file.write(text.encode());file.flush();os.fsync(file.fileno())
        os.replace(temp,path)

def peer_blocks(text):
    # Preserve all interface content and every untouched peer exactly.
    return re.split(r'(?im)^\s*\[Peer\]\s*$',text)

def synchronize(container,iface,path,tool):
    stripped=require(context_run(container,[tool+'-quick','strip',path]),'Strip configuration')
    require(context_run(container,[tool,'syncconf',iface,'/dev/stdin'],stripped.encode()),'Synchronize peers')

def mutate_client(params):
    container,iface,path,tool,text,config,peers=selected_tunnel(params)
    action=params['action'];name=str(params.get('name') or '').strip()
    token=time.strftime('%Y%m%d-%H%M%S')+'-'+os.urandom(4).hex()
    tablepath=os.path.dirname(path)+'/clientsTable'
    tabletext=mutation_table_read(container,tablepath)
    table=json_value(tabletext,[])
    if tabletext and not isinstance(table,list): raise RemoteError('Unsupported clientsTable format; no changes made.')
    if tabletext and not isinstance(json_value(tabletext,None),list): raise RemoteError('Invalid clientsTable JSON; no changes made.')
    export=None;public=params.get('public_key');address=None;ipv6_address=None
    if action=='client.create':
        keepalive=client_keepalive(params,config)
        addresses=[v.strip() for v in config.get('Address','').split(',') if v.strip()]
        network=next((ipaddress.ip_interface(v) for v in addresses if ':' not in v),None)
        if network is None or network.network.num_addresses>65536: raise RemoteError('An IPv4 tunnel subnet /16 or smaller is required.')
        used={str(network.ip)}
        for peer in peers:
            for value in peer.get('AllowedIPs','').split(','):
                if value.strip():
                    parsed=ipaddress.ip_network(value.strip(),strict=False)
                    if parsed.version==4:
                        if parsed.num_addresses>256: raise RemoteError('Routed peer subnets require manual IP allocation.')
                        used.update(str(i) for i in parsed)
        address=next((str(ip) for ip in network.network.hosts() if str(ip) not in used),None)
        if not address: raise RemoteError('Tunnel subnet has no free client IPv4 address.')
        ipv6=next((ipaddress.ip_interface(v) for v in addresses if ':' in v),None)
        if ipv6:
            used6={str(ipv6.ip)}
            for peer in peers:
                for value in peer.get('AllowedIPs','').split(','):
                    if value.strip() and ':' in value:
                        parsed=ipaddress.ip_network(value.strip(),strict=False)
                        if parsed.num_addresses>256:raise RemoteError('Routed IPv6 peer subnets require manual IP allocation.')
                        used6.update(str(ip) for ip in parsed)
            candidate=int(ipv6.network.network_address)+1
            last=min(int(ipv6.network.broadcast_address),candidate+65535)
            while candidate<=last:
                value=str(ipaddress.IPv6Address(candidate))
                if value not in used6:ipv6_address=value;break
                candidate+=1
            if not ipv6_address:raise RemoteError('No available IPv6 client address in the allocation window.')
        private=require(context_run(container,[tool,'genkey']),'Generate private key').strip()
        public=require(context_run(container,[tool,'pubkey'],(private+'\n').encode()),'Derive public key').strip()
        psk=require(context_run(container,[tool,'genpsk']),'Generate preshared key').strip()
        validate_key(private);validate_key(public);validate_key(psk)
        serverpub=require(context_run(container,[tool,'show',iface,'public-key']),'Read server public key').strip();validate_key(serverpub)
        port=intvalue(config.get('ListenPort'))
        if not 1<=port<=65535: raise RemoteError('Invalid tunnel listen port.')
        dns=str(params.get('dns') or '1.1.1.1, 1.0.0.1')
        for value in dns.split(','): ipaddress.ip_address(value.strip())
        allowed=str(params.get('allowed_ips') or '0.0.0.0/0, ::/0')
        for value in allowed.split(','): ipaddress.ip_network(value.strip(),strict=False)
        endpoint=str(REQUEST['host']);endpoint='['+endpoint+']' if ':' in endpoint else endpoint
        client_addresses=address+'/32'+(', '+ipv6_address+'/128' if ipv6_address else '')
        export='[Interface]\nAddress = '+client_addresses+'\nDNS = '+dns+'\nPrivateKey = '+private+'\n'
        export_parameters=dict(config,**client_cps_parameters(text,config))
        for key in AWG_PARAMETERS:
            value=export_parameters.get(key)
            if value: export+=key+' = '+value+'\n'
        export+='\n[Peer]\nPublicKey = '+serverpub+'\nPresharedKey = '+psk+'\nAllowedIPs = '+allowed+'\nEndpoint = '+endpoint+':'+str(port)+'\nPersistentKeepalive = '+keepalive+'\n'
        text=text.rstrip()+'\n\n[Peer]\nPublicKey = '+public+'\nPresharedKey = '+psk+'\nAllowedIPs = '+client_addresses+'\n'
        table.append({'clientId':public,'userData':{'clientName':name,'creationDate':datetime.datetime.now(datetime.timezone.utc).isoformat()},'clientIp':address})
    elif action=='client.delete':
        blocks=peer_blocks(text);new=[blocks[0]]
        for block in blocks[1:]:
            _,items=parse_config('[Peer]\n'+block)
            if not items or items[0].get('PublicKey')!=public:new.append('[Peer]\n'+block)
        text=''.join(new)
        table=[entry for entry in table if not isinstance(entry,dict) or entry.get('clientId')!=public]
    elif action=='client.rename':
        entry=next((entry for entry in table if isinstance(entry,dict) and entry.get('clientId')==public),None)
        if entry is None:
            entry={'clientId':public,'userData':{}};table.append(entry)
        if not isinstance(entry.get('userData'),dict):entry['userData']={}
        entry['userData']['clientName']=name
    backup=backup_file(container,path,token)
    tablebackup=backup_file(container,tablepath,token) if tabletext else None
    try:
        if action!='client.rename':
            write_atomic(container,path,text,token)
            synchronize(container,iface,path,tool)
        write_atomic(container,tablepath,json.dumps(table,ensure_ascii=False,indent=2)+'\n',token)
    except Exception:
        original=context_read(container,backup)
        write_atomic(container,path,original,token+'-rollback')
        if tablebackup: write_atomic(container,tablepath,context_read(container,tablebackup),token+'-rollback')
        if action!='client.rename': synchronize(container,iface,path,tool)
        raise
    return {'action':action,'public_key':public,'address':address,'ipv6_address':ipv6_address,'name':name,'backup':backup,
            'config':export,'filename':re.sub(r'[^A-Za-z0-9_.-]','_',name)[:64]+'.conf' if export else None,
            'message':'Изменение применено.','completed_at':now()}

def update_compose_container(params):
    name=params['container'];validate_container(name)
    info=json_value(require(run(['docker','inspect',name]),'Inspect container'),[])
    if not info:raise RemoteError('Container does not exist.')
    current=info[0];compose=compose_context(current,params)
    token=time.strftime('%Y%m%d-%H%M%S')+'-'+os.urandom(4).hex()
    backupdir='/var/backups/awg-control/'+token
    os.makedirs(backupdir,mode=0o700,exist_ok=False)
    os.chmod(backupdir,0o700)
    def save(path,text):
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(fd,'w') as file:file.write(text)
    save(backupdir+'/inspect.json',json.dumps(current,indent=2))
    for index,path in enumerate(compose['files']):save(backupdir+'/compose-'+str(index)+'.yml',readfile(path,4*1024*1024))
    backupimage='awg-control-backup:'+token
    require(run(['docker','commit','--pause=true',name,backupimage],timeout=50),'Back up previous container filesystem')
    override=backupdir+'/rollback.yml'
    save(override,'services:\n  '+compose['service']+':\n    image: '+json.dumps(backupimage)+'\n    pull_policy: never\n')
    rollback=compose['base']+['-f',override,'up','-d','--no-deps',compose['service']]
    save(backupdir+'/rollback-command.json',json.dumps(rollback,indent=2))
    # A failed pull does not alter the running container. Replacement failures
    # are handled with the same original Compose files plus the backup image.
    require(run(compose['base']+['pull',compose['service']],timeout=90,limit=1024*1024),'Pull Compose service image')
    try:
        require(run(compose['base']+['up','-d','--no-deps',compose['service']],timeout=45,limit=1024*1024),'Recreate Compose service')
        deadline=time.monotonic()+20
        healthy=False
        while time.monotonic()<deadline:
            ids=require(run(compose['base']+['ps','-q',compose['service']]),'Locate updated service').splitlines()
            if ids:
                inspected=json_value(require(run(['docker','inspect']+ids),'Check updated service'),[])
                states=[entry.get('State',{}) for entry in inspected]
                if states and all(state.get('Running') and state.get('Health',{}).get('Status') not in ('starting','unhealthy') for state in states):
                    healthy=True;break
            time.sleep(1)
        if not healthy:raise RemoteError('Updated Compose service did not become running/healthy within 20 seconds.')
    except Exception as error:
        restored=run(rollback,timeout=45,limit=1024*1024)
        if restored['ok']:raise RemoteError('Deployment failed; previous filesystem image restored. '+str(error))
        raise RemoteError('Deployment and automatic rollback both failed. Use '+backupdir+'/rollback-command.json. '+str(error))
    return {'action':'container.update','message':'Compose service updated and checked.',
            'backup':backupdir,'backup_image':backupimage,'rollback_command':rollback,
            'completed_at':now(),'service':compose['service'],'project':compose['project']}

def execute_action(params):
    if REQUEST.get('protected') or REQUEST.get('host')=='192.0.2.10': raise RemoteError('Protected production server: writes are permanently disabled.')
    if not REQUEST.get('write_allowed'): raise RemoteError('Read-only server: writes are disabled.')
    if params.get('confirmed') is not True: raise RemoteError('A reviewed and confirmed action plan is required.')
    # Also protect a DNS alias that resolves to this server from inside its own
    # network. The bridge already performs a separate local DNS guard.
    ips=run(['ip','-j','address','show'])
    if any(address.get('local')=='192.0.2.10' for interface in json_value(ips['stdout'],[]) for address in interface.get('addr_info',[])):
        raise RemoteError('Protected production IP detected on the remote host.')
    plan=plan_action(params)
    expected=params.get('expected_precondition')
    if not isinstance(expected,str) or not re.fullmatch(r'[a-f0-9]{64}',expected):
        raise RemoteError('A plan with a saved remote-state precondition is required.')
    if plan['precondition']!=expected:
        raise RemoteError('Remote configuration changed after review. Create a new action plan.')
    if not plan['executable']: raise RemoteError('This action is available as a plan only. '+ ' '.join(plan['warnings']))
    action=params['action']
    if action=='container.update':
        lockname='/tmp/awg-control-container-'+hashlib.sha256(params['container'].encode()).hexdigest()[:24]+'.lock'
        fd=os.open(lockname,os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(fd,'w') as lock:
            try:fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise RemoteError('Another update of this container is in progress.')
            if plan_action(params)['precondition']!=expected:
                raise RemoteError('Compose configuration changed while acquiring the lock. Create a new plan.')
            return update_compose_container(params)
    if action.startswith('client.'):
        # Serialize app-managed mutations. O_NOFOLLOW avoids symlink attacks.
        lockname='/tmp/awg-control-'+hashlib.sha256((str(params.get('container'))+str(params.get('config_path'))).encode()).hexdigest()[:24]+'.lock'
        fd=os.open(lockname,os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(fd,'w') as lock:
            fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
            if plan_action(params)['precondition']!=expected:
                raise RemoteError('Remote client configuration changed while acquiring the lock. Create a new plan.')
            return mutate_client(params)
    if action.startswith('container.'):
        result=run(['docker',action.split('.')[1],params['container']],timeout=35)
        require(result,'Container action')
    elif action.startswith('service.'):
        require(run(['systemctl',action.split('.')[1],params['service']],timeout=35),'Change service state')
    elif action=='host.reboot':
        # systemd schedules the reboot after the SSH response has been sent.
        require(run(['systemd-run','--unit=awg-control-reboot-'+str(int(time.time())),
                     '--on-active=5s','/usr/bin/systemctl','reboot']),'Schedule reboot')
    return {'action':action,'message':'Команда выполнена.','completed_at':now(),'plan':plan}

def inspect_container(params):
    name=str(params.get('container') or '');validate_container(name)
    containers,_=docker_objects()
    selected=next((item for item in containers if item['name']==name or item['id']==name),None)
    if not selected: raise RemoteError('Container not found.')
    return selected

def main():
    try:
        operation=REQUEST['operation'];params=REQUEST.get('params') or {}
        if operation=='snapshot':data=collect_snapshot()
        elif operation=='logs':data=log_output(params)
        elif operation=='inspect':data=inspect_container(params)
        elif operation=='plan':data=plan_action(params)
        elif operation=='execute':data=execute_action(params)
        else:raise RemoteError('Unsupported remote operation.')
        print(json.dumps({'ok':True,'data':data},ensure_ascii=False))
    except Exception as error:
        print(json.dumps({'ok':False,'error':redact(str(error))[:2000],'code':'remote_error'},ensure_ascii=False))

if __name__=='__main__':main()
'''


def main():
    try:
        payload = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(payload) > MAX_INPUT:
            raise BridgeError('Request exceeds the safe input limit.', 'input_limit')
        request = json.loads(payload)
        operation = request.get('operation')
        if operation not in OPERATIONS:
            raise BridgeError('Unknown operation.', 'validation')
        server, params = request.get('server') or {}, request.get('params') or {}
        validate_server(server)
        if operation == 'execute':
            if protected_server(server):
                raise BridgeError('Protected production server: writes are permanently disabled.', 'protected_server')
            if server.get('read_only', True) is not False:
                raise BridgeError('Read-only server: writes are disabled.', 'read_only')
            if params.get('confirmed') is not True:
                raise BridgeError('A reviewed and confirmed action plan is required.', 'confirmation_required')
        result = {'ok': True, 'data': fingerprint(server)} if operation == 'fingerprint' else ssh_call(server, operation, params)
    except BridgeError as error:
        result = {'ok': False, 'error': str(error), 'code': error.code}
    except (ValueError, TypeError, KeyError, OSError):
        result = {'ok': False, 'error': 'Invalid request or unavailable local SSH dependency.', 'code': 'validation'}
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
