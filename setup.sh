#!/bin/bash

# Скрипт для автоматической сборки и установки ASTRACAT DNR
# Выход при любой ошибке
set -e

# 1. Проверка на наличие прав root
if [ "$(id -u)" -ne 0 ]; then
  echo "Этот скрипт должен быть запущен с правами root. Пожалуйста, используйте sudo." >&2
  exit 1
fi

echo "--- Автоматический установщик ASTRACAT DNR ---"
echo "Этот скрипт установит зависимости, соберет и установит DNS-сервер."

# 2. Определение и установка зависимостей
echo "[1/6] Определение пакетного менеджера и установка зависимостей..."

INSTALL_CMD=""
PACKAGES=""

if command -v apt-get &> /dev/null; then
    INSTALL_CMD="apt-get install -y"
    PACKAGES="build-essential autoconf automake libtool"
    apt-get update
elif command -v dnf &> /dev/null; then
    INSTALL_CMD="dnf install -y"
    PACKAGES="gcc-c++ make autoconf automake libtool glibc-devel"
elif command -v yum &> /dev/null; then
    INSTALL_CMD="yum install -y"
    PACKAGES="gcc-c++ make autoconf automake libtool glibc-devel"
else
    echo "Ошибка: Не удалось найти поддерживаемый пакетный менеджер (apt-get, dnf, yum)."
    echo "Пожалуйста, установите следующие пакеты вручную: build-essential (или эквивалент), autoconf, automake, libtool."
    exit 1
fi

echo "Используется команда: $INSTALL_CMD $PACKAGES"
$INSTALL_CMD $PACKAGES

# 3. Генерация скриптов сборки
echo "[2/6] Запуск autoreconf для генерации сборочных скриптов..."
# Сначала очистим старые артефакты, если они есть
if [ -f "Makefile" ]; then
    make distclean || echo "Не удалось выполнить 'make distclean', но это не критично."
fi
autoreconf -fiv

# 4. Конфигурация проекта
echo "[3/6] Запуск ./configure для настройки проекта..."
# Устанавливаем бинарные файлы в /usr/local/bin, а сервис systemd в /lib/systemd/system
./configure --prefix=/usr/local --with-systemdsystemunitdir=/lib/systemd/system

# 5. Сборка проекта
echo "[4/6] Запуск make для компиляции..."
make

# 6. Установка проекта
echo "[5/6] Запуск 'make install' для установки бинарного файла и сервиса..."
make install

# 7. Проверка и исправление dnr.service
echo "[6/6] Перезагрузка демона systemd для применения нового сервиса..."

# Путь к исполняемому файлу
BIN_PATH="/usr/local/bin/DNR"

# Путь к сервисному файлу
SERVICE_PATH="/lib/systemd/system/dnr.service"

# Проверка существования файла
if [ ! -f "$BIN_PATH" ]; then
    echo "Ошибка: Бинарный файл не найден по пути $BIN_PATH"
    exit 1
fi

# Проверка существования сервисного файла
if [ ! -f "$SERVICE_PATH" ]; then
    echo "Ошибка: Сервисный файл не найден по пути $SERVICE_PATH"
    exit 1
fi

# Исправление пути в dnr.service
echo "[7/6] Исправление пути в dnr.service..."

# Используем # в качестве разделителя, чтобы избежать конфликта с / в пути
sed -i "s#^ExecStart=.*#ExecStart=${BIN_PATH}#" "$SERVICE_PATH"

# Добавляем User и Group, если не указаны
if ! grep -q "^User=" "$SERVICE_PATH"; then
    sed -i '1i User=root' "$SERVICE_PATH"
fi

if ! grep -q "^Group=" "$SERVICE_PATH"; then
    sed -i '1i Group=root' "$SERVICE_PATH"
fi

# Перезагрузка демона systemd
systemctl daemon-reload

echo
echo "--- Установка успешно завершена! ---"
echo
echo "Что дальше?"
echo
echo "1. Бинарный файл 'DNR' установлен в $BIN_PATH."
echo "2. Файл сервиса 'dnr.service' установлен в $SERVICE_PATH."
echo "   Вы можете изменить его, если нужно (например, поменять порт)."
echo
echo "3. Для управления сервисом используйте команды:"
echo "   sudo systemctl start dnr       # Запустить сервис"
echo "   sudo systemctl enable dnr      # Включить автозапуск при загрузке"
echo "   sudo systemctl status dnr      # Проверить статус"
echo "   sudo systemctl stop dnr        # Остановить сервис"
echo
echo "4. Для просмотра логов:"
echo "   journalctl -u dnr -f"
