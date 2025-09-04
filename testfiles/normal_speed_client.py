#!/usr/bin/env python3
import asyncio
import websockets
import time
from datetime import datetime

async def limited_speed_sender():
    uri = "ws://localhost:8082"
    message_count = 0
    start_time = time.time()

    try:
        async with websockets.connect(uri) as websocket:
            print(f"Limited speed client connected to {uri}")

            while True:
                message_count += 1
                timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                message = f"Message #{message_count} at {timestamp}"

                try:
                    await websocket.send(message)
                    print(f"[{timestamp}] Sent: {message}")
                    response = await asyncio.wait_for(websocket.recv(), timeout=2.0)
                    print(f"[{timestamp}] Received: {response[:50]}...")

                except asyncio.TimeoutError:
                    print(f"[{timestamp}] Timeout waiting for response")
                except Exception as e:
                    print(f"[{timestamp}] Error: {e}")

                await asyncio.sleep(1)

                if message_count % 10 == 0:
                    elapsed = time.time() - start_time
                    rate = message_count / elapsed
                    print(f"=== Sent {message_count} messages in {elapsed:.1f}s (rate: {rate:.2f} msg/s) ===")

    except websockets.exceptions.ConnectionClosed:
        print("Limited speed client: Connection closed")
    except Exception as e:
        print(f"Limited speed client error: {e}")


if __name__ == "__main__":
    asyncio.run(limited_speed_sender())
