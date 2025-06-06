#!/usr/bin/env python3

import asyncio
import json
import ssl
from typing import Dict, List, Optional, Union
import aiohttp
from rich.console import Console
from rich.table import Table
from ratelimit import limits, sleep_and_retry
from aiohttp import ClientTimeout, TCPConnector

# Rate limits (per minute)
RATE_LIMIT = 45
CALLS_PER_MINUTE = 45

# Timeout settings (in seconds)
TIMEOUT = 10
MAX_RETRIES = 3

console = Console()

class IPLookupService:
    def __init__(self):
        self.apis = {
            'ip-api': 'http://ip-api.com/json/{ip}',
            'ipwhois': 'https://ipwhois.app/json/{ip}'
        }
        self.session = None
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

    async def init_session(self):
        if not self.session:
            timeout = ClientTimeout(total=TIMEOUT)
            connector = TCPConnector(ssl=self.ssl_context)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector
            )

    async def close_session(self):
        if self.session:
            await self.session.close()
            self.session = None

    @sleep_and_retry
    @limits(calls=CALLS_PER_MINUTE, period=60)
    async def query_api(self, api_name: str, ip: str, retry_count: int = 0) -> Optional[Dict]:
        """Query a specific API with rate limiting and retry logic."""
        try:
            url = self.apis[api_name].format(ip=ip)
            async with self.session.get(url) as response:
                if response.status == 200:
                    try:
                        return await response.json()
                    except json.JSONDecodeError:
                        console.print(f"[yellow]Invalid JSON response from {api_name}[/yellow]")
                        return None
                elif response.status == 429:
                    console.print(f"[yellow]Rate limit exceeded for {api_name}[/yellow]")
                elif response.status == 403:
                    console.print(f"[yellow]Access forbidden for {api_name} - may require API key[/yellow]")
                else:
                    console.print(f"[red]Error querying {api_name}: {response.status}[/red]")
        except aiohttp.ClientError as e:
            if retry_count < MAX_RETRIES:
                console.print(f"[yellow]Retrying {api_name} (attempt {retry_count + 1}/{MAX_RETRIES})[/yellow]")
                await asyncio.sleep(1)  # Wait before retry
                return await self.query_api(api_name, ip, retry_count + 1)
            console.print(f"[red]Error with {api_name} after {MAX_RETRIES} retries: {str(e)}[/red]")
        except Exception as e:
            console.print(f"[red]Unexpected error with {api_name}: {str(e)}[/red]")
        return None

    def safe_get(self, obj: Union[Dict, None], *keys: str, default: any = None) -> any:
        """Safely get nested dictionary values."""
        if not isinstance(obj, dict):
            return default
        current = obj
        for key in keys:
            if not isinstance(current, dict):
                return default
            current = current.get(key, default)
            if current is None:
                return default
        return current

    async def lookup_ip(self, ip: str) -> Dict:
        """Query all APIs and aggregate results."""
        await self.init_session()
        
        tasks = [self.query_api(api_name, ip) for api_name in self.apis]
        results = await asyncio.gather(*tasks)
        
        # Aggregate results
        aggregated = {
            'ip': ip,
            'country': None,
            'city': None,
            'region': None,
            'isp': None,
            'latitude': None,
            'longitude': None,
            'timezone': None,
            'sources': []
        }

        for api_name, result in zip(self.apis.keys(), results):
            if result and isinstance(result, dict):
                aggregated['sources'].append(api_name)
                # Map fields based on API response structure
                if api_name == 'ip-api':
                    aggregated.update({
                        'country': self.safe_get(result, 'country'),
                        'city': self.safe_get(result, 'city'),
                        'region': self.safe_get(result, 'regionName'),
                        'isp': self.safe_get(result, 'isp'),
                        'latitude': self.safe_get(result, 'lat'),
                        'longitude': self.safe_get(result, 'lon'),
                        'timezone': self.safe_get(result, 'timezone')
                    })
                elif api_name == 'ipwhois':
                    aggregated.update({
                        'country': self.safe_get(result, 'country'),
                        'city': self.safe_get(result, 'city'),
                        'region': self.safe_get(result, 'region'),
                        'isp': self.safe_get(result, 'connection', 'isp'),
                        'latitude': self.safe_get(result, 'latitude'),
                        'longitude': self.safe_get(result, 'longitude'),
                        'timezone': self.safe_get(result, 'timezone', 'id')
                    })

        await self.close_session()
        return aggregated

def display_results(data: Dict):
    """Display results in a formatted table."""
    table = Table(title=f"IP Lookup Results for {data['ip']}")
    
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Sources", style="yellow")

    fields = [
        ('Country', 'country'),
        ('City', 'city'),
        ('Region', 'region'),
        ('ISP', 'isp'),
        ('Latitude', 'latitude'),
        ('Longitude', 'longitude'),
        ('Timezone', 'timezone')
    ]

    for label, key in fields:
        value = data.get(key)
        if value is not None:
            table.add_row(label, str(value), ', '.join(data['sources']))

    if not data['sources']:
        console.print("[red]No data available from any API sources[/red]")
    else:
        console.print(table)

async def main():
    service = IPLookupService()
    
    while True:
        ip = input("\nEnter IP address (or 'quit' to exit): ").strip()
        if ip.lower() == 'quit':
            break

        try:
            results = await service.lookup_ip(ip)
            display_results(results)
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")

if __name__ == "__main__":
    asyncio.run(main()) 