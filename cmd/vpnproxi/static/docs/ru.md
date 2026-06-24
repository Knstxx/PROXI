# Инструкция оператора VPNproxi

## Сценарий развертывания

1. VPNproxi устанавливается на чистый Debian или Ubuntu VPS.
2. Installer запрашивает логин и пароль администратора; UI открывается по ссылке и этим логином/паролем.
3. Текущий host доступен в блоке Endpoint.
4. DNS `A`-запись должна указывать VPN-домен на публичный IP этого сервера.
5. Этот домен указывается в `VPN domain`, затем добавляется внешняя 3x-ui/Xray ссылка.
6. Если внешний маршрут менялся, сначала выполняется `Проверить маршрут`, затем конфигурация применяется на Linux VPS.

## Минимальный быстрый старт

1. Подготовь один gateway VPS с публичным IP.
2. Направь DNS `A`-запись, например `vpn.example.com`, на этот gateway.
3. Открой `500/udp` и `4500/udp` для IPsec.
4. Открой `80/tcp` и `443/tcp`, если UI публикуется через `--domain`.
5. Запусти installer на gateway:

```bash
sudo ./scripts/install.sh --domain vpn.example.com --port 8443 --email admin@example.com
```

6. Войди в UI.
7. Укажи `VPN domain = vpn.example.com`.
8. Добавь IPsec-клиентов в блоке `IPsec clients`.
9. Вставь внешнюю ссылку, выполни `Проверить маршрут`, выбери режим маршрутизации и нажми `Применить`.
10. На клиентском устройстве создай IKEv2-подключение с параметрами:
   - server: `vpn.example.com`
   - remote ID: `vpn.example.com`
   - username/password: из блока `IPsec clients`.

## Что нужно на внешнем сервере

VPNproxi управляет gateway, а не внешним exit-node.

На внешнем сервере уже должен быть рабочий outbound-узел 3x-ui/Xray и одна экспортированная share link. Самый простой рабочий вариант такой:

1. Установить и настроить 3x-ui на внешнем VPS.
2. Создать там одного клиента.
3. Скопировать его share link.
4. Вставить эту ссылку в VPNproxi.
5. Выполнить `Проверить маршрут`.
6. Применить черновик на gateway.

Поддерживаемые форматы ссылок: `vless`, `vmess`, `trojan`, `ss`, `hysteria2`, `hy2`, `wireguard`, `wg`.

## DNS и IPsec host

`Адрес IPsec сервера` — это адрес, который клиенты должны указывать как сервер VPN.

Если `VPN domain` пустой, VPNproxi показывает текущий host из браузера. На реальном VPS, открытом по IP, это обычно публичный IP сервера. Для production лучше использовать DNS-имя, а не голый IP.

Рекомендуемый production-вариант:

- DNS-запись: `vpn.example.com A <server-public-ip>`.
- Значение `VPN domain`: `vpn.example.com`.
- Installer запускается с `--domain vpn.example.com`, если для UI требуется HTTPS через Caddy.
- UDP-порты `500` и `4500` должны быть доступны для IPsec.
- UI-порт по возможности оставляй доступным только из доверенной админской сети.

## Сертификаты

В VPNproxi есть две отдельные истории с сертификатами:

- HTTPS для UI обслуживает Caddy, если installer запущен с `--domain`.
- IPsec identity обслуживает StrongSwan через поля `IPsec certificate` и `IPsec private key`.

Installer генерирует локальный CA и серверный IPsec-сертификат с доменом в SAN. Клиенты должны доверять `/etc/swanctl/x509ca/vpnproxi-ca.crt`, либо нужно использовать цепочку сертификатов, которой клиентские устройства уже доверяют. Если `IPsec certificate` указывает на fullchain bundle, Apply разделит его на leaf-сертификат для StrongSwan и intermediate-сертификаты в `/etc/swanctl/x509ca`.

## Доступ к UI

Админский логин и bcrypt-хэш пароля хранятся в `/etc/vpnproxi/admin.json`. Сессионная cookie подписывается секретом из этого же файла и выставляется как `HttpOnly`.

## Внешний маршрут

В поле внешнего маршрута указывается одна 3x-ui/Xray ссылка. После изменения ссылки выполняется `Проверить маршрут`, а затем черновик применяется на хост. Поддерживаются `vless`, `vmess`, `trojan`, `ss`, `hysteria2`, `hy2`, `wireguard` и `wg`.

Эта ссылка становится внешним Xray outbound. Она используется только в режимах `Selective Xray` и `Force Xray`.

## Маршрутизация

Режим маршрутизации определяет, что происходит с трафиком IPsec-клиентов:

- `Direct NAT` — стабильный production-режим. Трафик идет напрямую через шлюз с NAT, Xray не участвует в datapath.
- `Selective Xray` — через внешний outbound уходит только трафик, совпавший с proxy-правилами.
- `Force Xray` — весь трафик клиента уходит через внешний outbound, кроме явных direct-исключений. Локальный DNS при этом остается прямым, чтобы не ломать резолвинг.

В `Selective Xray` через внешний outbound трафик уходит при совпадении с proxy-правилами:

- домены через внешний сервер
- IP/CIDR через внешний сервер
- порты через внешний сервер
- списки блокировок

Direct-правила имеют приоритет выше proxy-правил. Используй их для банков, внутренних ресурсов, приватных подсетей и всего, что должно оставаться локально.

## Источник списков блокировок

При включенных `Списках блокировок` VPNproxi добавляет в маршрутизацию Xray правила `geosite:ru-blocked-all`, `geoip:ru-blocked`, `geoip:ru-blocked-community` и `geoip:telegram`.

Эта галка использует blocked-датасеты runetfreedom и обновляется таймером systemd. В `Статус хоста` показывается время последнего обновления загруженных списков.

Файлы данных обновляются сгенерированным таймером systemd `vpnproxi-geodata.timer`. Таймер запускает `/usr/local/bin/vpnproxi-geodata-update.sh`, который скачивает актуальные release-файлы:

- `geoip.dat` из `https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geoip.dat`
- `geosite.dat` из `https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat`

Файлы устанавливаются в `/usr/local/share/xray` и используются Xray как стандартные `geoip.dat` и `geosite.dat`.

## Что делает Применить

Применить записывает сгенерированные файлы Xray и StrongSwan, запускает firewall/sysctl reconciler, проверяет конфигурацию Xray, перезапускает Xray, перечитывает StrongSwan credentials и перезапускает StrongSwan.

На macOS приложение работает только в local-only режиме. Реальное применение доступно только на Linux.

## Настройки в UI

В UI намеренно вынесены только операторские настройки:

- внешняя outbound-ссылка
- VPN domain и subnet
- режим маршрутизации
- Xray transparent port; legacy mark и table оставлены для совместимости
- пути к IPsec certificate и key
- правила маршрутизации
- IPsec пользователи

Advanced file paths, geodata paths, DNS servers и пути generated scripts остаются на безопасных дефолтах, чтобы панель не превращалась в перегруженный конфигуратор.
