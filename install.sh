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

# --- Начало исправления для неработающего репозитория ---
RESTORE_APT_SOURCES=false
SOURCES_FILE="/etc/apt/sources.list"
# Проверяем, существует ли файл и содержит ли он проблемную строку
if [ -f "$SOURCES_FILE" ] && grep -q "repo.powerdns.com/ubuntu" "$SOURCES_FILE"; then
    echo "Обнаружен потенциально неработающий репозиторий PowerDNS. Временно отключаю его на время установки..."
    # Комментируем проблемную строку и создаем резервную копию
    sed -i.bak '/repo.powerdns.com\/ubuntu/s/^/#/' "$SOURCES_FILE"
    RESTORE_APT_SOURCES=true
    echo "Резервная копия оригинального файла создана: $SOURCES_FILE.bak"
fi
# --- Конец исправления ---

# 1. Установка зависимостей
echo "[1/5] Установка необходимых пакетов (build-essential, libldns-dev)..."
if ! command -v apt-get &> /dev/null; then
    echo "Ошибка: apt-get не найден. Этот скрипт предназначен для Debian-подобных систем (Ubuntu, Mint и т.д.)."
    # Восстанавливаем файл sources.list, если он был изменен
    if [ "$RESTORE_APT_SOURCES" = true ]; then
        mv "$SOURCES_FILE.bak" "$SOURCES_FILE"
    fi
    exit 1
fi

# Запускаем apt-get update и обрабатываем возможную ошибку
if ! apt-get update; then
    echo "Ошибка при выполнении apt-get update. Возможно, проблемы с другими репозиториями."
    # Восстанавливаем файл sources.list, если он был изменен
    if [ "$RESTORE_APT_SOURCES" = true ]; then
        echo "Восстановление оригинального файла /etc/apt/sources.list..."
        mv "$SOURCES_FILE.bak" "$SOURCES_FILE"
    fi
    exit 1
fi

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
User=root
Group=root
ExecStart=/usr/local/bin/DNR -p 5353
Restart=on-failure
StandardOutput=journal
StandardError=journal
SyslogIdentifier=dnr

[Install]
WantedBy=multi-user.target
EOF

# Перезагрузка конфигурации systemd для распознавания нового сервиса
systemctl daemon-reload

# --- Начало восстановления sources.list ---
if [ "$RESTORE_APT_SOURCES" = true ]; then
    echo "Восстановление оригинального файла /etc/apt/sources.list..."
    mv "$SOURCES_FILE.bak" "$SOURCES_FILE"
    echo "Файл восстановлен."
fi
# --- Конец восстановления ---

echo
echo "--- Установка завершена! ---"
echo
echo "Бинарный файл 'DNR' был установлен в /usr/local/bin/DNR"
echo "Файл сервиса systemd был создан в /etc/systemd/system/dnr.service"
echo
echo "Для управления сервисом вы можете использовать следующие команды:"
echo "  sudo systemctl start dnr.service"
echo "  sudo systemctl enable dnr.service"
echo "  sudo systemctl status dnr.service"
echo "  sudo systemctl stop dnr.service"
echo "  sudo journalctl -u dnr.service -f"
echo
echo "По умолчанию сервис настроен на работу на порту 5353."
