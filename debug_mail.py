
import trio
import sys
import os

# Add src to path
sys.path.append(os.path.join(os.getcwd(), "src"))

from sentinelle.engines.mail.core import MailEngine

async def test():
    engine = MailEngine()
    
    def on_complete(res):
        print(f"COMPLETE: {res.get('domain')}")
        
    def log(msg):
        print(f"LOG: {msg}")
        
    print("Starting search...")
    results = await engine.run_search("test@gmail.com", on_complete=on_complete, log_callback=log)
    print(f"Finished. Found {len(results)} results.")

if __name__ == "__main__":
    trio.run(test)
