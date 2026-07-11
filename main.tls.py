import asyncio
import os
import ssl
import struct
import socket
import uuid
import logging
import websockets

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Получаем переменные окружения
UUID_STR = os.getenv('UUID', '10889da6-14ea-4cc8-97fa-6c0bc410f121')
PORT = int(os.getenv('PORT', 3000))

# Парсим и сохраняем эталонный UUID в виде байтов для быстрого сравнения
try:
    EXPECTED_UUID_BYTES = uuid.UUID(UUID_STR).bytes
except ValueError:
    logging.error("Неверный формат UUID. Убедитесь, что UUID корректен.")
    exit(1)


def parse_handshake(buf: bytes):
    """
    Разбирает сообщение рукопожатия (handshake) клиента VLESS
    и извлекает версию, UUID, целевой хост/порт и смещение.
    Основано на: https://xtls.github.io/development/protocols/vless.html
    """
    offset = 0
    version = buf[offset]
    offset += 1

    client_id = buf[offset:offset+16]
    offset += 16

    opt_len = buf[offset]
    offset += 1 + opt_len

    command = buf[offset]
    offset += 1

    port = struct.unpack('>H', buf[offset:offset+2])[0]
    offset += 2

    addr_type = buf[offset]
    offset += 1

    if addr_type == 1:  # IPv4
        host = socket.inet_ntop(socket.AF_INET, buf[offset:offset+4])
        offset += 4
    elif addr_type == 2:  # DOMAIN
        domain_len = buf[offset]
        offset += 1
        host = buf[offset:offset+domain_len].decode('utf-8')
        offset += domain_len
    elif addr_type == 3:  # IPv6
        host = socket.inet_ntop(socket.AF_INET6, buf[offset:offset+16])
        offset += 16
    else:
        raise ValueError(f"Неподдерживаемый тип адреса: {addr_type}")

    return version, client_id, command, host, port, offset


async def handle_client(websocket, *args, **kwargs):
    """
    Обрабатывает входящее WebSocket соединение и устанавливает TCP туннель
    к запрошенному ресурсу.
    """
    try:
        # Ожидаем первое сообщение (handshake)
        msg = await websocket.recv()
        
        # VLESS всегда использует бинарные сообщения
        if isinstance(msg, str):
            await websocket.close()
            return

        # Парсим VLESS пакет
        version, client_id, command, host, port, offset = parse_handshake(msg)

        # Проверяем UUID (авторизация)
        if client_id != EXPECTED_UUID_BYTES:
            logging.warning("Попытка подключения с неверным UUID")
            await websocket.close()
            return

        # Отправляем ответ об успешном рукопожатии [version, 0]
        await websocket.send(bytes([version, 0]))

        # Устанавливаем TCP соединение с целевым сервером
        try:
            reader, writer = await asyncio.open_connection(host, port)
        except Exception as e:
            logging.error(f"Не удалось подключиться к {host}:{port}: {e}")
            await websocket.close()
            return

        # Записываем остаток первоначального сообщения в сокет
        payload = msg[offset:]
        if payload:
            writer.write(payload)
            await writer.drain()

        # Асинхронные задачи для двунаправленной передачи данных
        async def ws_to_tcp():
            try:
                async for message in websocket:
                    writer.write(message)
                    await writer.drain()
            except websockets.exceptions.ConnectionClosed:
                pass
            except Exception as e:
                logging.debug(f"Ошибка WS -> TCP: {e}")
            finally:
                writer.close()

        async def tcp_to_ws():
            try:
                while True:
                    data = await reader.read(8192)
                    if not data:
                        break
                    await websocket.send(data)
            except websockets.exceptions.ConnectionClosed:
                pass
            except Exception as e:
                logging.debug(f"Ошибка TCP -> WS: {e}")
            finally:
                await websocket.close()

        # Запускаем пересылку трафика
        await asyncio.gather(ws_to_tcp(), tcp_to_ws())

    except Exception as e:
        logging.error(f"Ошибка обработки рукопожатия: {e}")
        await websocket.close()


async def main():
    # Настройка TLS / SSL
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        # Убедитесь, что файлы cert.pem и key.pem находятся в той же директории
        ssl_context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
    except Exception as e:
        logging.error(f"Ошибка загрузки сертификатов TLS: {e}")
        exit(1)

    logging.info(f"VLESS сервер запущен на порту {PORT}")
    
    # Запускаем WebSocket сервер
    async with websockets.serve(handle_client, "0.0.0.0", PORT, ssl=ssl_context):
        await asyncio.Future()  # Работает вечно


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Сервер остановлен.")