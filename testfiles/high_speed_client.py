#!/usr/bin/env python3
import asyncio
import websockets
import time
from datetime import datetime

async def high_speed_sender():
    uri = "ws://localhost:8082"  
    message_count = 0
    start_time = time.time()
    
    try:
        async with websockets.connect(uri) as websocket:
            print(f"High speed client connected to {uri}")
            
           
            while True:
                message_count += 1
                timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                message = f"High speed message #{message_count} at {timestamp}"
                
                try:
                    await websocket.send(message)
                    print(f"[{timestamp}] Sent: {message}")
                    
                    response = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                    print(f"[{timestamp}] Received: {response[:50]}...")
                    
                except asyncio.TimeoutError:
                    print(f"[{timestamp}] Timeout waiting for response")
                except Exception as e:
                    print(f"[{timestamp}] Error: {e}")
                
                await asyncio.sleep(0.05)
                
                if message_count % 100 == 0:
                    elapsed = time.time() - start_time
                    rate = message_count / elapsed
                    print(f"=== Sent {message_count} messages in {elapsed:.1f}s (rate: {rate:.1f} msg/s) ===")
                    
    except websockets.exceptions.ConnectionClosed:
        print("High speed client: Connection closed")
    except Exception as e:
        print(f"High speed client error: {e}")

if __name__ == "__main__":
    asyncio.run(high_speed_sender())
