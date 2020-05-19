
# ipk-scan.cpp

  

ipk-scan je projekt, který skenuje UDP porty, které jsou zadané v argumentu -u, --pu. TCP porty, které jsou zadané v argumentu -t, --pt.
na IP adrese, která může být zadaná kdekoliv v argumentech může být i ve stylu doménového jména. Rozhraní, přes které se bude komunikovat, se argument -i pokud nebude zadaný, tak se vybere první neloopbackkové rozhraní. Pro vypsání pomocného výpisu můžete zadat -h, ? nebo -help
  

## Make

  

Pro přeložení projektu použijte příkaz make. Ujistěte se, že make file je ve stejném souboru jako ipk-scan.cpp

  

```bash

make

```

 ## Run
 Pro spuštění programu spusťte přeložený program jak je uvedeno v okénku dole.

```bash

sudo ./ipk-scan --pu or -u <UDP ports> --pt or -t<TCP ports> -i<interface> <Domein name or IP adres>

```

## Neimplementováno

V této verzi projektu není implementováno více procesové řešení. Z toho důvodu může být program pomalý při skenování velkého množství portů.


## Soubory
ipk-scan.cpp
makefile
manual.pdf
readme.md
