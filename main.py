import asyncio
import os
import struct
import uuid
import socket
import sys

try:
    import websockets
    from websockets.server import serve
except ImportError:
    print("Пожалуйста, установите библиотеку websockets перед запуском:")
    print("pip install websockets")
    sys.exit(1)

UUID_STR = os.environ.get('UUID', '10889da6-14ea-4cc8-97fa-6c0bc410f121')
PORT = int(os.environ.get('PORT', 3000))

try:
    EXPECTED_UUID = uuid.UUID(UUID_STR).bytes
except ValueError:
    print(f"Неверный формат UUID: {UUID_STR}")
    sys.exit(1)


def parse_handshake(data: bytes):
    """
    Разбирает сообщение рукопожатия (handshake) клиента VLESS
    и извлекает версию, UUID, целевой хост/порт и смещение.
    Основано на: https://xtls.github.io/development/protocols/vless.html
    """
    offset = 0
    version = data[offset]
    offset += 1

    client_uuid = data[offset:offset+16]
    offset += 16

    opt_len = data[offset]
    offset += 1 + opt_len

    command = data[offset]
    offset += 1

    # Чтение 2 байтов порта (Big-Endian)
    port = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2

    address_type = data[offset]
    offset += 1

    # Определение целевого адреса
    if address_type == 1:  # IPV4
        host = socket.inet_ntop(socket.AF_INET, data[offset:offset+4])
        offset += 4
    elif address_type == 2:  # DOMAIN
        domain_len = data[offset]
        offset += 1
        host = data[offset:offset+domain_len].decode('utf-8')
        offset += domain_len
    elif address_type == 3:  # IPV6
        host = socket.inet_ntop(socket.AF_INET6, data[offset:offset+16])
        offset += 16
    else:
        raise ValueError(f"Неподдерживаемый тип адреса: {address_type}")

    return version, client_uuid, command, host, port, offset


async def handle_client(websocket):
    """
    Асинхронный обработчик для каждого нового WebSocket-соединения.
    """
    try:
        # Получаем первое сообщение (handshake)
        first_msg = await websocket.recv()
        if isinstance(first_msg, str):
            # Протокол VLESS использует исключительно бинарные данные
            return 

        try:
            version, client_uuid, command, host, port, offset = parse_handshake(first_msg)
        except Exception:
            await websocket.close()
            return

        # Проверяем UUID
        if client_uuid != EXPECTED_UUID:
            await websocket.close()
            return

        # Отправляем ответ VLESS (версия и 0 - успешное подключение)
        await websocket.send(bytes([version, 0]))

        # Устанавливаем TCP-соединение с целевым хостом
        try:
            reader, writer = await asyncio.open_connection(host, port)
        except Exception:
            await websocket.close()
            return

        # Если в первом пакете остались данные (полезная нагрузка), отправляем их
        remaining_data = first_msg[offset:]
        if remaining_data:
            writer.write(remaining_data)
            await writer.drain()

        # Корутина для пересылки данных из WebSocket -> в TCP
        async def ws_to_tcp():
            try:
                async for message in websocket:
                    if isinstance(message, bytes):
                        writer.write(message)
                        await writer.drain()
            except Exception:
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        # Корутина для пересылки данных из TCP -> в WebSocket
        async def tcp_to_ws():
            try:
                while True:
                    data = await reader.read(8192)  # Читаем порциями по 8KB
                    if not data:
                        break
                    await websocket.send(data)
            except Exception:
                pass
            finally:
                await websocket.close()

        # Запускаем двунаправленную передачу данных параллельно
        await asyncio.gather(ws_to_tcp(), tcp_to_ws())

    except Exception:
        # Тихо закрываем сокет при любых обрывах связи (аналогично try/catch в Node)
        try:
            await websocket.close()
        except Exception:
            pass


async def main():
    print(f"Сервер запущен на порту {PORT}")
    # Запускаем WebSocket сервер на всех интерфейсах (0.0.0.0)
    async with serve(handle_client, "0.0.0.0", PORT):
        await asyncio.Future()  # Поддерживаем процесс запущенным бесконечно


if __name__ == "__main__":
    # Точка входа в программу
    asyncio.run(main())