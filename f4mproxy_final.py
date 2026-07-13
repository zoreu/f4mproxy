# unified_proxy_complete.py - Proxy unificado (Canais F4M + MP4 com seek)
import socket
import threading
import struct
import random
import time
import os
import re
from urllib.parse import urlparse, unquote, urljoin, quote
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import binascii
import ssl
from collections import deque
import gzip
import zlib

# ==================== CONFIGURAÇÕES ====================
PROXY_PORT = 9090
CACHE_DURATION_SECONDS = 3
CACHE_MAX_CHUNKS = 250
MAX_RETRIES = 7
RETRY_DELAY = 0.5
BUFFER_SIZE = 32768
AOVIVO_M3U8 = True

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Safari/537.36"
)

# ==================== DNS CUSTOM ====================
class SimpleDNS:
    def __init__(self):
        self.cache = {}
        self.dns_servers = ["1.1.1.1", "8.8.8.8", "208.67.222.222"]
        self.original_getaddrinfo = socket.getaddrinfo
        socket.getaddrinfo = self._resolver

    def _build_query(self, domain):
        transaction_id = random.randint(0, 65535)
        header = struct.pack(">HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
        qname = b"".join(
            bytes([len(part)]) + part.encode() for part in domain.split(".")
        ) + b"\x00"
        return header + qname + struct.pack(">HH", 1, 1)

    def _parse_response(self, data):
        try:
            answer_count = struct.unpack(">H", data[6:8])[0]
            offset = 12
            while data[offset] != 0:
                offset += 1
            offset += 5

            for _ in range(answer_count):
                offset += 2
                rtype, _, _, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
                offset += 10
                if rtype == 1 and rdlength == 4:
                    ip = struct.unpack(">BBBB", data[offset:offset + 4])
                    return ".".join(map(str, ip))
                offset += rdlength
        except Exception:
            pass
        return None

    def resolve(self, domain):
        if domain in self.cache and self.cache[domain]["expires"] > time.time():
            return self.cache[domain]["ip"]

        for dns in self.dns_servers:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                query = self._build_query(domain)
                sock.sendto(query, (dns, 53))
                data, _ = sock.recvfrom(512)
                sock.close()
                ip = self._parse_response(data)
                if ip:
                    self.cache[domain] = {"ip": ip, "expires": time.time() + 3600}
                    return ip
            except Exception:
                continue
        return None

    def _resolver(self, host, port, *args, **kwargs):
        try:
            socket.inet_aton(host)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, port))]
        except Exception:
            ip = self.resolve(host)
            if ip:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]
        return self.original_getaddrinfo(host, port, *args, **kwargs)


dns = SimpleDNS()


# ==================== CACHE CIRCULAR PARA CANAIS ====================
class CircularBuffer:
    def __init__(self, max_seconds=5, max_chunks=250):
        self.buffer = deque(maxlen=max_chunks)
        self.timestamps = deque(maxlen=max_chunks)
        self.max_seconds = max_seconds
        self.total_bytes = 0
        self.lock = threading.Lock()
        self.last_update = 0
        self.stream_started = False

    def add_chunk(self, chunk):
        with self.lock:
            self.buffer.append(chunk)
            self.timestamps.append(time.time())
            self.total_bytes += len(chunk)
            self.last_update = time.time()
            
            cutoff = time.time() - self.max_seconds
            while self.timestamps and self.timestamps[0] < cutoff:
                removed = self.buffer.popleft()
                self.timestamps.popleft()
                self.total_bytes -= len(removed)

    def get_recovery_chunks(self, duration=3):
        with self.lock:
            if not self.buffer:
                return []
            cutoff = time.time() - duration
            recovery = []
            for i, ts in enumerate(self.timestamps):
                if ts >= cutoff:
                    recovery.append(self.buffer[i])
            if not recovery and self.buffer:
                recovery = list(self.buffer)[-20:]
            return recovery

    def get_continuous_chunks(self, count=30):
        with self.lock:
            if not self.buffer:
                return []
            return list(self.buffer)[-count:]

    def clear(self):
        with self.lock:
            self.buffer.clear()
            self.timestamps.clear()
            self.total_bytes = 0
            self.stream_started = False


# ==================== CACHE MP4 (para seek rapido) ====================
class MP4Cache:
    def __init__(self, max_chunks=250):
        self.chunks = {}
        self.max_chunks = max_chunks
        self.lock = threading.Lock()
        self.total_size = 0
        self.content_length = None

    def add_chunk(self, start_byte, data):
        if not data:
            return
        with self.lock:
            if start_byte not in self.chunks:
                self.chunks[start_byte] = data
                self.total_size += len(data)
                while len(self.chunks) > self.max_chunks:
                    oldest = min(self.chunks.keys())
                    self.total_size -= len(self.chunks[oldest])
                    del self.chunks[oldest]

    def get_range(self, start, end):
        with self.lock:
            keys = sorted(self.chunks.keys())
            if not keys:
                return None

            result = bytearray()
            pos = start

            while pos < end:
                found = False
                for chunk_start in keys:
                    chunk = self.chunks[chunk_start]
                    chunk_end = chunk_start + len(chunk)
                    if chunk_start <= pos < chunk_end:
                        offset = pos - chunk_start
                        take = min(end - pos, chunk_end - pos)
                        result.extend(chunk[offset:offset + take])
                        pos += take
                        found = True
                        break
                if not found:
                    return None

            return bytes(result)


# ==================== PROXY HANDLER ====================
class UnifiedProxy:
    def __init__(self):
        self.channel_caches = {}
        self.mp4_caches = {}
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        self.stream_lock = threading.Lock()
        self.cache_lock = threading.Lock()

    def get_random_user_agent(self):
        random_bytes = binascii.b2a_hex(os.urandom(20))[:32].decode('ascii')
        return f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random_bytes} Safari/537.36"

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = "127.0.0.1"
        finally:
            s.close()
        return ip

    def extract_url_from_path(self, path):
        # /tsdownloader?url=XXX
        if '/tsdownloader' in path and '?url=' in path:
            params = path.split('?', 1)[1]
            for param in params.split('&'):
                if param.startswith('url='):
                    return unquote(param[4:])
        
        # /?url=XXX
        if path.startswith('/?url='):
            url_part = path[6:]
            if '&' in url_part:
                url_part = url_part.split('&', 1)[0]
            return unquote(url_part)

        # /http:// ou /https://
        if path.startswith('/http://') or path.startswith('/https://'):
            return unquote(path[1:])

        # http:// ou https:// direto
        if path.startswith('http://') or path.startswith('https://'):
            return unquote(path)

        return None

    def get_channel_cache(self, url):
        clean_url = re.sub(r'(_=\d+|timestamp=\d+|t=\d+|seq=\d+)', '', url)
        with self.stream_lock:
            if clean_url not in self.channel_caches:
                self.channel_caches[clean_url] = CircularBuffer(CACHE_DURATION_SECONDS, CACHE_MAX_CHUNKS)
            return self.channel_caches[clean_url]

    def get_mp4_cache(self, url):
        clean_url = re.sub(r'(_=\d+|timestamp=\d+|t=\d+|seq=\d+)', '', url)
        with self.cache_lock:
            if clean_url not in self.mp4_caches:
                self.mp4_caches[clean_url] = MP4Cache(CACHE_MAX_CHUNKS)
            return self.mp4_caches[clean_url]

    # ==================== FETCH PARA CANAIS (DO F4M PROXY) ====================
    def fetch_channel_with_fallback(self, url, headers=None, range_header=None, cache=None):
        if headers is None:
            headers = {}
        
        for attempt in range(MAX_RETRIES):
            if attempt == 0:
                user_agent = CHROME_UA
                ua_type = "CHROME"
            else:
                user_agent = self.get_random_user_agent()
                ua_type = f"RANDOM_{attempt}"
            
            req_headers = {
                'User-Agent': user_agent,
                'Accept': '*/*',
                'Accept-Language': 'pt-BR,pt;q=0.9',
                'Connection': 'keep-alive'
            }
            
            for key, value in headers.items():
                if key.lower() not in ['host', 'connection', 'content-length', 'range', 'user-agent', 'accept-encoding']:
                    req_headers[key] = value
            
            if range_header:
                req_headers['Range'] = range_header
            
            print(f"    🔄 Tentativa {attempt + 1}/{MAX_RETRIES} - UA: {ua_type}")
            
            try:
                req = Request(url, headers=req_headers)
                
                if url.startswith('https'):
                    response = urlopen(req, timeout=15, context=self.ssl_context)
                else:
                    response = urlopen(req, timeout=15)
                
                status_code = response.getcode()
                content_encoding = response.headers.get('content-encoding', '').lower()
                
                if status_code not in [200, 206]:
                    print(f"    ⚠️ Status {status_code} recebido")
                    return None, status_code, None
                
                print(f"    ✅ Sucesso! Status: {status_code}")
                return response, status_code, content_encoding
                
            except HTTPError as e:
                print(f"    ❌ HTTP {e.code} com UA: {ua_type}")
                if e.code in [400, 401, 403, 404, 406, 451, 500, 502, 503, 504, 523]:
                    return None, e.code, None
                
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY * (attempt + 1))
                    continue
                return None, e.code, None
                
            except Exception as e:
                print(f"    ❌ Erro: {e}")
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY * (attempt + 1))
                    continue
                return None, 0, None
        
        return None, 0, None

    def rewrite_m3u8_urls(self, playlist_content, base_url, proxy_host):
        try:
            #TARGET_DURATION = re.findall(r'#EXT-X-TARGETDURATION:(.*?)\n', playlist_content)[0]
            segments_number = int(playlist_content.count('/hl'))
            NEXT_SEGMENT = segments_number * 2
            ENABLE_AOVIVO = True
        except:
            ENABLE_AOVIVO = False
        def replace_url(match):
            segment = match.group(0).strip()
            if segment.startswith('#') or not segment:
                return segment
            try:
                absolute = urljoin(base_url + '/', segment)
                if absolute.endswith('.ts') or absolute.endswith('.m3u8') or '/hl' in absolute.lower() or 'track' in absolute.lower():
                    # GARANTIR AOVIVO
                    if AOVIVO_M3U8 and '/hl' in absolute and '.ts' in absolute and ENABLE_AOVIVO:
                        try:
                            atual_ts = '_' + re.findall(r'_(.*?).ts', absolute)[0] + '.ts'
                            new_ts = '_' + str(int(re.findall(r'_(.*?).ts', absolute)[0]) + NEXT_SEGMENT) + '.ts'
                            # print('segmento atual: ', atual_ts)
                            # print('novo segmento: ', new_ts)
                            new_absolute = absolute.replace(atual_ts, new_ts)
                            return f"http://{proxy_host}/tsdownloader?url={quote(new_absolute)}"
                        except:
                            pass

                    return f"http://{proxy_host}/tsdownloader?url={quote(absolute)}"
                return segment
            except:
                return segment
        
        rewritten = re.sub(r'^(?!#)\S+', replace_url, playlist_content, flags=re.MULTILINE)
        return rewritten

    # ==================== HANDLE CANAL (DO F4M PROXY - FUNCIONA) ====================
    def handle_channel_stream(self, url, headers, client_socket):
        cache = self.get_channel_cache(url)
        response = None
        stream_active = True
        
        try:
            print(f"  📡 Iniciando stream de canal: {url[:80]}...")
            
            response, status_code, content_encoding = self.fetch_channel_with_fallback(url, headers, None, cache)
            
            if response is None:
                print(f"  💾 Usando cache inicial para iniciar stream")
                recovery_chunks = cache.get_recovery_chunks(CACHE_DURATION_SECONDS)
                if recovery_chunks:
                    media_type = 'video/mp2t'
                    headers_line = f"HTTP/1.1 200 OK\r\n"
                    headers_line += f"Content-Type: {media_type}\r\n"
                    headers_line += f"Access-Control-Allow-Origin: *\r\n"
                    headers_line += f"Cache-Control: no-cache\r\n"
                    headers_line += f"Connection: keep-alive\r\n\r\n"
                    client_socket.send(headers_line.encode())
                    
                    for chunk in recovery_chunks:
                        try:
                            client_socket.send(chunk)
                            time.sleep(0.03)
                        except:
                            stream_active = False
                            break
                else:
                    self.send_error(client_socket, 503, "Sem cache disponível")
                    return
            
            if response and status_code in [200, 206]:
                content_type = response.headers.get('content-type', '').lower()
                content_url = response.geturl()
                
                if 'mpegurl' in content_type or '.m3u8' in content_url.lower():
                    print(f"  📋 Processando M3U8...")
                    raw_content = response.read()
                    
                    try:
                        if content_encoding == 'gzip':
                            content = gzip.decompress(raw_content)
                        elif content_encoding == 'deflate':
                            content = zlib.decompress(raw_content)
                        else:
                            content = raw_content
                    except:
                        content = raw_content
                    
                    try:
                        playlist_text = content.decode('utf-8', errors='ignore')
                        print(f"  📄 M3U8 recebido, tamanho: {len(playlist_text)} bytes")
                        
                        proxy_host = f"{self.get_local_ip()}:{PROXY_PORT}"
                        base_url = content_url.rsplit('/', 1)[0]
                        rewritten = self.rewrite_m3u8_urls(playlist_text, base_url, proxy_host)
                        
                        response.close()
                        
                        response_headers = f"HTTP/1.1 200 OK\r\n"
                        response_headers += f"Content-Type: application/vnd.apple.mpegurl\r\n"
                        response_headers += f"Content-Length: {len(rewritten)}\r\n"
                        response_headers += f"Access-Control-Allow-Origin: *\r\n"
                        response_headers += f"Cache-Control: no-cache\r\n\r\n"
                        
                        client_socket.send(response_headers.encode())
                        client_socket.send(rewritten.encode('utf-8'))
                        print(f"  ✅ M3U8 reescrito e enviado ({len(rewritten)} bytes)")
                        return
                    except Exception as e:
                        print(f"  ❌ Erro M3U8: {e}")
                        return
                
                media_type = 'video/mp2t'
                status = 206 if status_code == 206 else 200
                
                print(f"  🎬 Stream de vídeo iniciado")
                
                headers_line = f"HTTP/1.1 {status} OK\r\n"
                headers_line += f"Content-Type: {media_type}\r\n"
                headers_line += f"Access-Control-Allow-Origin: *\r\n"
                headers_line += f"Cache-Control: no-cache\r\n"
                headers_line += f"Connection: keep-alive\r\n"
                
                if 'content-length' in response.headers:
                    headers_line += f"Content-Length: {response.headers['content-length']}\r\n"
                
                headers_line += "\r\n"
                client_socket.send(headers_line.encode())
                
                cache.stream_started = True
                consecutive_errors = 0
                cache_mode = False
                
                while stream_active:
                    try:
                        if response:
                            chunk = response.read(BUFFER_SIZE)
                            if chunk:
                                cache.add_chunk(chunk)
                                client_socket.send(chunk)
                                consecutive_errors = 0
                                cache_mode = False
                            else:
                                print(f"  📦 Fim do stream")
                                break
                        else:
                            if not cache_mode:
                                print(f"  💾 Entrando em modo cache...")
                                cache_mode = True
                            
                            cache_chunks = cache.get_continuous_chunks(30)
                            if cache_chunks:
                                for chunk in cache_chunks:
                                    try:
                                        client_socket.send(chunk)
                                        time.sleep(0.03)
                                    except:
                                        stream_active = False
                                        break
                            
                            try:
                                print(f"  🔄 Tentando reconectar...")
                                new_response, new_status, _ = self.fetch_channel_with_fallback(
                                    url, headers, f"bytes={cache.total_bytes}-", cache
                                )
                                if new_response and new_status in [200, 206]:
                                    if response:
                                        response.close()
                                    response = new_response
                                    cache_mode = False
                                    print(f"  ✅ Reconectado!")
                                    continue
                            except:
                                pass
                            
                            time.sleep(1)
                            
                    except (socket.error, BrokenPipeError):
                        print(f"  📴 Cliente desconectou")
                        break
                    except Exception as e:
                        print(f"  ⚠️ Erro: {e}")
                        consecutive_errors += 1
                        
                        if not cache_mode:
                            print(f"  💾 Ativando modo cache")
                            cache_mode = True
                        
                        if consecutive_errors >= 3:
                            try:
                                if response:
                                    response.close()
                                    response = None
                                
                                new_response, new_status, _ = self.fetch_channel_with_fallback(
                                    url, headers, f"bytes={cache.total_bytes}-", cache
                                )
                                if new_response and new_status in [200, 206]:
                                    response = new_response
                                    cache_mode = False
                                    consecutive_errors = 0
                                    print(f"  ✅ Reconectado!")
                                    continue
                            except:
                                pass
                        
                        if cache_mode:
                            cache_chunks = cache.get_continuous_chunks(20)
                            for chunk in cache_chunks:
                                try:
                                    client_socket.send(chunk)
                                    time.sleep(0.03)
                                except:
                                    stream_active = False
                                    break
                
        except Exception as e:
            print(f"  💥 Erro fatal: {e}")
            try:
                cache_chunks = cache.get_continuous_chunks(50)
                for chunk in cache_chunks:
                    try:
                        client_socket.send(chunk)
                        time.sleep(0.03)
                    except:
                        break
            except:
                pass
        finally:
            if response:
                try:
                    response.close()
                except:
                    pass
            print(f"  🛑 Stream finalizado")

    # ==================== FETCH PARA MP4 (ORIGINAL - INALTERADO) ====================
    def fetch_mp4_with_retry(self, url, range_header=None, method='GET'):
        for attempt in range(MAX_RETRIES):
            try:
                parsed = urlparse(url)
                referer = f"{parsed.scheme}://{parsed.netloc}/"

                headers = {
                    'User-Agent': CHROME_UA,
                    'Accept': 'video/mp4,video/*;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'pt-BR,pt;q=0.9',
                    'Accept-Encoding': 'identity',
                    'Connection': 'keep-alive',
                    'Referer': referer,
                    'Origin': f"{parsed.scheme}://{parsed.netloc}",
                }

                if range_header:
                    headers['Range'] = range_header

                req = Request(url, headers=headers, method=method)
                
                if url.startswith('https'):
                    response = urlopen(req, timeout=30, context=self.ssl_context)
                else:
                    response = urlopen(req, timeout=30)
                    
                return response

            except Exception as e:
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY)
                    continue
                print(f"  Erro fetch MP4 ({method} {range_header}): {e}")
                return None

    def _parse_range(self, range_header):
        if not range_header:
            return None
        match = re.search(r'bytes=(\d+)-(\d*)', range_header)
        if not match:
            return None
        start = int(match.group(1))
        end = int(match.group(2)) if match.group(2) else None
        return start, end

    def _parse_total_size(self, headers):
        content_range = headers.get('Content-Range', '') or headers.get('content-range', '')
        match = re.search(r"/(\d+)$", content_range)
        if match:
            return int(match.group(1))
        content_length = headers.get('Content-Length') or headers.get('content-length')
        if content_length and content_length.isdigit():
            return int(content_length)
        return None

    def _detect_mp4(self, url):
        lower = url.lower()
        if any(ext in lower for ext in ['.mp4', '.mkv', '.webm', '.f4v', '.mov', '.avi']):
            return True
        if '/play/' in lower:
            return True
        if 'xtream' in lower and ('/movie/' in lower or '/series/' in lower):
            return True
        return False

    # ==================== HANDLE MP4 (ORIGINAL - INALTERADO) ====================
    def handle_mp4_stream(self, url, method, req_headers, client_socket):
        cache = self.get_mp4_cache(url)
        range_header = req_headers.get('range')
        parsed_range = self._parse_range(range_header)

        if parsed_range and parsed_range[1] is not None:
            start, end = parsed_range
            cached = cache.get_range(start, end + 1)
            if cached:
                total = cache.content_length or '*'
                self.send_response(
                    client_socket,
                    status=206,
                    reason='Partial Content',
                    headers={
                        'Content-Type': 'video/mp4',
                        'Accept-Ranges': 'bytes',
                        'Content-Length': str(len(cached)),
                        'Content-Range': f'bytes {start}-{start + len(cached) - 1}/{total}',
                    },
                )
                if method not in ('HEAD', 'OPTIONS'):
                    client_socket.send(cached)
                print(f"  MP4 seek do cache: {start}-{start + len(cached) - 1}")
                return

        upstream = self.fetch_mp4_with_retry(url, range_header=range_header, method=method)

        if not upstream and range_header:
            upstream = self.fetch_mp4_with_retry(url, range_header='bytes=0-', method=method)

        if not upstream:
            self.send_error(client_socket, 503, 'Falha ao conectar ao servidor de origem')
            return

        status = upstream.getcode()
        reason = {
            200: 'OK',
            206: 'Partial Content',
            416: 'Range Not Satisfiable',
        }.get(status, 'OK')

        total_size = self._parse_total_size(upstream.headers)
        if total_size:
            cache.content_length = total_size

        upstream_headers = {
            'Content-Type': upstream.headers.get('Content-Type', 'video/mp4'),
            'Accept-Ranges': upstream.headers.get('Accept-Ranges', 'bytes'),
        }
        if upstream.headers.get('Content-Length'):
            upstream_headers['Content-Length'] = upstream.headers.get('Content-Length')
        if upstream.headers.get('Content-Range'):
            upstream_headers['Content-Range'] = upstream.headers.get('Content-Range')

        self.send_response(client_socket, status=status, reason=reason, headers=upstream_headers)

        if method in ('HEAD', 'OPTIONS'):
            upstream.close()
            return

        sent = 0
        pos = 0
        if status == 206:
            content_range = upstream.headers.get('Content-Range', '')
            match = re.search(r'bytes\s+(\d+)-', content_range)
            if match:
                pos = int(match.group(1))
            elif parsed_range:
                pos = parsed_range[0]

        try:
            while True:
                chunk = upstream.read(BUFFER_SIZE)
                if not chunk:
                    break
                cache.add_chunk(pos, chunk)
                pos += len(chunk)
                client_socket.send(chunk)
                sent += len(chunk)
        except (BrokenPipeError, socket.error):
            pass
        except Exception as e:
            print(f"  Erro stream MP4: {e}")
        finally:
            upstream.close()

        print(f"  MP4 finalizado: {sent / 1024 / 1024:.2f} MB")

    def send_response(self, sock, status=200, reason='OK', headers=None):
        response = f"HTTP/1.1 {status} {reason}\r\n"
        base_headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
            'Access-Control-Allow-Headers': 'Range, Origin, Content-Type, Accept',
            'Connection': 'close',
            'Cache-Control': 'no-cache',
        }
        if headers:
            base_headers.update(headers)

        for k, v in base_headers.items():
            response += f"{k}: {v}\r\n"
        response += "\r\n"
        sock.send(response.encode('utf-8', errors='ignore'))

    def send_error(self, client_socket, code, message):
        reason = {
            400: 'Bad Request',
            404: 'Not Found',
            416: 'Range Not Satisfiable',
            500: 'Internal Server Error',
            503: 'Service Unavailable',
        }.get(code, 'Error')
        body = message.encode('utf-8', errors='ignore')
        self.send_response(
            client_socket,
            status=code,
            reason=reason,
            headers={
                'Content-Type': 'text/plain; charset=utf-8',
                'Content-Length': str(len(body)),
            },
        )
        try:
            client_socket.send(body)
        except Exception:
            pass

    # ==================== HANDLE REQUEST PRINCIPAL ====================
    def handle_request(self, client_socket, request_data):
        try:
            request_str = request_data.decode('utf-8', errors='ignore')
            lines = request_str.split('\r\n')
            if not lines:
                return

            first_line = lines[0].split(' ')
            if len(first_line) < 2:
                return

            method = first_line[0].upper()
            path = first_line[1]

            if method == 'OPTIONS':
                self.send_response(client_socket, 200, 'OK')
                return

            normalized_headers = {}
            for line in lines[1:]:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    normalized_headers[key.lower()] = value

            url = self.extract_url_from_path(path)
            if not url:
                local_ip = self.get_local_ip()
                html = (
                    "<html><body>"
                    "<h2>Unified Proxy - Canais F4M + MP4 com Seek</h2>"
                    f"<p><b>Canais:</b> http://{local_ip}:{PROXY_PORT}/tsdownloader?url=URL_DO_CANAL</p>"
                    f"<p><b>MP4/M3U8:</b> http://{local_ip}:{PROXY_PORT}/?url=URL_DO_VIDEO</p>"
                    "<ul>"
                    "<li>✅ Canais: Cache circular 5s, fallback automático, reconexão</li>"
                    "<li>✅ MP4: Suporte a Range/SEEK (original funcionando)</li>"
                    "<li>✅ M3U8: Reescreve URLs para proxy</li>"
                    "</ul>"
                    "</body></html>"
                ).encode('utf-8')
                self.send_response(
                    client_socket,
                    200,
                    'OK',
                    {'Content-Type': 'text/html; charset=utf-8', 'Content-Length': str(len(html))},
                )
                client_socket.send(html)
                return

            url_lower = url.lower()
            
            # Roteamento
            if self._detect_mp4(url):
                # MP4 com suporte a seek (ORIGINAL INALTERADO)
                self.handle_mp4_stream(url, method, normalized_headers, client_socket)
            else:
                # CANAIS (F4M, HLS, TS, etc) - DO F4M PROXY QUE FUNCIONA
                self.handle_channel_stream(url, normalized_headers, client_socket)

        except Exception as e:
            print(f"  Erro: {e}")
            try:
                self.send_error(client_socket, 500, str(e))
            except Exception:
                pass


# ==================== SERVIDOR ====================
class UnifiedServer:
    def __init__(self, port=PROXY_PORT):
        self.port = port
        self.proxy = UnifiedProxy()
        self.running = True

    def handle_client(self, client_socket, addr):
        try:
            client_socket.settimeout(30)
            request_data = b''
            while True:
                try:
                    chunk = client_socket.recv(8192)
                    if not chunk:
                        break
                    request_data += chunk
                    if b'\r\n\r\n' in request_data:
                        break
                except socket.timeout:
                    break
            if request_data:
                self.proxy.handle_request(client_socket, request_data)
        except Exception as e:
            print(f"Erro cliente {addr}: {e}")
        finally:
            try:
                client_socket.close()
            except Exception:
                pass

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', self.port))
        server.listen(100)

        local_ip = self.proxy.get_local_ip()
        print(f"""
╔════════════════════════════════════════╗
║               F4M PROXY                ║
╠════════════════════════════════════════╣
║  Proxy: http://{local_ip}:{self.port}        ║
╚════════════════════════════════════════╝
        """)

        while self.running:
            try:
                client_socket, addr = server.accept()
                t = threading.Thread(target=self.handle_client, args=(client_socket, addr))
                t.daemon = True
                t.start()
            except KeyboardInterrupt:
                self.running = False
                break
            except Exception as e:
                print(f"Erro servidor: {e}")

        server.close()


if __name__ == "__main__":
    srv = UnifiedServer()
    try:
        srv.start()
    except KeyboardInterrupt:
        print("Proxy encerrado.")
