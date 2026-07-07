import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from entra_scanner import EntraPrivilegeScanner

async def main():
    scanner = EntraPrivilegeScanner()
    await scanner.run_scan()

if __name__ == "__main__":
    asyncio.run(main())
