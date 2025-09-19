#!/bin/bash

# Скрипт для автоматической установки ASTRACAT DNR
# Выход при любой ошибке
set -e

# Проверка на наличие прав root
if [ "$(id -u)" -ne 0 ]; then
  echo "Этот скрипт должен быть запущен с правами root. Пожалуйста, используйте sudo." >&2
  exit 1
fi

echo "--- Автоматический установщик ASTRACAT DNR ---"

# 1. Установка зависимостей
echo "[1/5] Установка необходимых пакетов (build-essential, libldns-dev)..."
if ! command -v apt-get &> /dev/null; then
    echo "Ошибка: apt-get не найден. Этот скрипт предназначен для Debian-подобных систем (Ubuntu, Mint и т.д.)."
    exit 1
fi
apt-get update
apt-get install -y build-essential libc6-dev libldns-dev autoconf automake libtool

# 2. Подготовка сборочного окружения
echo "[2/5] Запуск autoreconf для генерации скриптов сборки..."
autoreconf -fiv

# 3. Конфигурация сборки
echo "[3/5] Запуск ./configure для настройки проекта..."
./configure

# 4. Сборка проекта
echo "[4/5] Запуск make для компиляции..."
make

# 5. Установка бинарного файла и сервиса
echo "[5/5] Установка бинарного файла DNR и сервиса systemd..."

# Установка бинарного файла в /usr/local/bin
install -m 755 src/DNR /usr/local/bin/DNR

# Создание файла сервиса systemd
SERVICE_FILE="/etc/systemd/system/dnr.service"
echo "Создание файла сервиса systemd: $SERVICE_FILE..."
cat > "$SERVICE_FILE" << EOF
[Unit]
Description=ASTRACAT DNR Recursive DNS Server
After=network.target

[Service]
Type=simple
# Для безопасности рекомендуется запускать сервис от имени непривилегированного пользователя.
# Создайте пользователя: useradd --system --no-create-home --shell /bin/false dnr
# И раскомментируйте следующие строки:
# User=dnr
# Group=dnr
User=root
Group=root

# Примечание: Порт 53 требует прав root или CAP_NET_BIND_SERVICE.
# В этом примере используется порт 5353. Вы можете изменить его при необходимости.
ExecStart=/usr/local/bin/DNR -p 5353
Restart=on-failure

# Конфигурация логирования
StandardOutput=journal
StandardError=journal
SyslogIdentifier=dnr

[Install]
WantedBy=multi-user.target
EOF

# Перезагрузка конфигурации systemd для распознавания нового сервиса
systemctl daemon-reload

echo
echo "--- Установка завершена! ---"
echo
echo "Бинарный файл 'DNR' был установлен в /usr/local/bin/DNR"
echo "Файл сервиса systemd был создан в /etc/systemd/system/dnr.service"
echo
echo "Для управления сервисом вы можете использовать следующие команды:"
echo "  sudo systemctl start dnr.service    # Запустить сервис"
echo "  sudo systemctl enable dnr.service   # Включить автозапуск при загрузке системы"
echo "  sudo systemctl status dnr.service   # Проверить статус сервиса"
echo "  sudo systemctl stop dnr.service     # Остановить сервис"
echo "  sudo journalctl -u dnr.service -f   # Просматривать логи в реальном времени"
echo
echo "По умолчанию сервис настроен на работу на порту 5353. Вы можете отредактировать файл сервиса, чтобы изменить порт или другие параметры."
