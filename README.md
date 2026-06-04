# f4mproxy
f4mproxy for XC PRO addon stremio

Tutorial:

1 - baixe o qpython+ no android

2 - copie o codigo abaixo

```python
import urllib.request
import ssl
url = 'https://raw.githack.com/zoreu/f4mproxy/main/f4mproxy_final.py'
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}
req = urllib.request.Request(url, headers=headers)
# ignora verificação SSL
context = ssl._create_unverified_context()
with urllib.request.urlopen(req, context=context) as response:
    code = response.read().decode('utf-8')
exec(code)
```

- no qpython clique em Editor e cole o codigo

- salve e dê o nome f4mproxy.py

- clique no play para rodar o proxy

pegue o endereço do proxy que aparece: exemplo: http://192.168.0.4:9090

vá na pagina do addon XC PRO e coloque onde pede f4m proxy.
