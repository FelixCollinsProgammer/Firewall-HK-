# 🛡️ Gazan Firewall 🛡️

[![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Простой XDP-файрвол для Linux, позволяющий контролировать сетевой трафик с помощью пользовательских правил для портов и блокировки ICMP 🚫. Идеально подходит для домашних серверов или сред разработки! 🏠

## ✨ Возможности

*   **Фильтрация по портам:** Блокировка подключений к определенным портам на основе SYN-пакетов. 🔒
*   **Контроль ICMP:** Включение и выключение ping (ICMP) запросов. 🏓
*   **Проверка HTTP/TLS:** Базовые проверки для уверенности, что порт 80 обслуживает HTTP, а 443 - HTTPS/TLS. ✅
*   **Интерактивное меню:** Легкое в использовании меню в терминале для управления настройками. ⚙️
*   **Логирование:** Запись заблокированного трафика для анализа. 📝

## 🚀 Быстрый старт

### Необходимые условия

*   Среда Linux 🐧
*   Python 3.6+ 🐍
*   Установленный `bcc` (BPF Compiler Collection): `sudo apt-get install bpfcc-tools` (Debian/Ubuntu)
*   Требуются права root (sudo) для запуска! 🔑

### Установка

1.  Клонируйте репозиторий: `git clone [your_repository_url]`
2.  Перейдите в директорию: `cd [your_repository_directory]`

### Использование

*   **Запуск интерактивного меню:** `sudo python3 network_guard.py --menu`
*   **Активация фильтра на интерфейсе:** `sudo python3 network_guard.py <сетевой_интерфейс>` (например, `sudo python3 network_guard.py eth0`)
*   **Добавить порты:** `sudo python3 network_guard.py --add <порт1,порт2,...>`
*   **Удалить порты:** `sudo python3 network_guard.py --del <порт1,порт2,...>`
*   **Показать текущие настройки:** `sudo python3 network_guard.py --show`
*   **Просмотреть логи:** `sudo python3 network_guard.py --logs`
*   **Помощь:** `sudo python3 network_guard.py --help`

## ⚙️ Конфигурация

Настройки файрвола (разрешенные порты, блокировка ICMP) хранятся в `./network_guard.conf`. Отредактируйте этот файл для настройки файрвола.

## 📝 Логирование

Заблокированный трафик записывается в `./network_guard.log`.

## 📄 Лицензия

Этот проект лицензирован в соответствии с лицензией MIT - см. файл `LICENSE` для подробностей.
