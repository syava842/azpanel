# azpanel

Веб-панель и агент для [AntiZapret-VPN](https://github.com/GubernievS/AntiZapret-VPN):
клиенты OpenVPN и WireGuard, мониторинг подключений, лимиты, маршрутизация,
telemt, AZ-WARP, прокси. Работает поверх родных скриптов AntiZapret, их
поведение не меняет.

## Требования

- Ubuntu 24.04+ или Debian 13+, amd64 или arm64, root.
- Установленный AntiZapret-VPN. Если его нет, установщик предложит поставить.
  AntiZapret-VPN ставится его собственным установщиком из
  `GubernievS/AntiZapret-VPN` (ветка `main`) так же, как в его README: этот
  шаг подписью azpanel не проверяется.

## Установка

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/syava842/azpanel/main/scripts/setup.sh)"
```

Скрипт скачивает последний релиз, проверяет подпись ed25519 и сумму, затем
запускает мастер `azpanel install`: тип установки, адрес и домен, способ
открытия панели (свой порт или префикс в существующем nginx), HTTPS, логин
администратора, бэкапы. До подтверждения мастер ничего не меняет.

Без вопросов (панель под префиксом `/azpanel/` в существующем nginx):

```bash
AZPANEL_MODE=panel+node AZPANEL_ACCESS=path AZPANEL_DOMAIN=vpn.example.com \
AZPANEL_ADMIN=admin AZPANEL_ADMIN_PASSWORD='пароль' \
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/syava842/azpanel/main/scripts/setup.sh)" -- --non-interactive
```

`AZPANEL_MODE`: `panel+node`, `node`, `panel`, `proxy`. `AZPANEL_ACCESS`:
`path`, `port` (свой порт, тогда ещё `AZPANEL_TLS`), `local` (только
127.0.0.1). Чего не хватает, мастер перечислит.

Конкретная версия: `AZPANEL_VERSION=1.2.3`.

## Обновление

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/syava842/azpanel/main/scripts/update.sh)"
```

С бэкапом и откатом при сбое; `--check` — только проверить.

## Пароль администратора

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/syava842/azpanel/main/scripts/change_passwd.sh)" -- логин
```

Или на сервере: `azpanel panel passwd --user логин`, список — `azpanel user list`.

## Удаление

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/syava842/azpanel/main/scripts/uninstall.sh)"
```

Перед удалением делается бэкап AntiZapret; AntiZapret и клиенты остаются.
`-- --purge` удаляет и `/opt/azpanel` (настройки, журналы).

## Раскладка

| путь | что |
| --- | --- |
| `/opt/azpanel/bin/azpanel` | программа; ссылка `/usr/local/bin/azpanel` |
| `/opt/azpanel/etc/` | `config.toml`, `secrets.env`, `install.env` |
| `/opt/azpanel/data/` | база панели, лимиты |
| `azpanel-node`, `azpanel-panel` | службы systemd |

Проверка установки: `azpanel doctor`.
