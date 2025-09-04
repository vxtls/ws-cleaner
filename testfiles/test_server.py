#!/usr/bin/env python3
import asyncio
import websockets
import json
from datetime import datetime

async def echo(websocket, path=None):
    print(f"New client connected from {websocket.remote_address}")
    message_count = 0
    
    try:
        async for message in websocket:
            message_count += 1
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print(f"[{timestamp}] Message #{message_count}: {message[:50]}...")
            
            await websocket.send(f"Echo: {message}")
            
    except websockets.exceptions.ConnectionClosed:
        print(f"Client disconnected: {websocket.remote_address}")
    except Exception as e:
        print(f"Error: {e}")

async def main():
    print("WebSocket Test Server starting on ws://localhost:8081")
    try:
        async with websockets.serve(echo, "localhost", 8081):
            print("Server running. Press Ctrl+C to stop.")
            await asyncio.Future()  # Run forever
    except TypeError:
        async with websockets.serve(echo, "localhost", 8081, path=None):
            print("Server running. Press Ctrl+C to stop.")
            await asyncio.Future()  # Run forever

if __name__ == "__main__":
    asyncio.run(main())
