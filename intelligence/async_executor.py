"""
Async Executor for Parallel OSINT Queries
Orchestrates concurrent data collection with rate limiting
"""

import asyncio
import aiohttp
import logging
from typing import List, Dict, Any, Callable, Optional
from dataclasses import dataclass
from datetime import datetime
import time


@dataclass
class TaskResult:
    """Result of an async task"""
    task_name: str
    success: bool
    data: Any
    error: Optional[str]
    duration: float


class AsyncExecutor:
    """Execute multiple OSINT queries in parallel with rate limiting"""
    
    def __init__(self, max_concurrent: int = 10, timeout: int = 30):
        """
        Initialize async executor.
        
        Args:
            max_concurrent: Maximum concurrent tasks
            timeout: Default timeout per task (seconds)
        """
        self.logger = logging.getLogger(__name__)
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def execute_task(
        self,
        task_name: str,
        func: Callable,
        *args,
        **kwargs
    ) -> TaskResult:
        """
        Execute a single async task with timeout and error handling.
        
        Args:
            task_name: Name of the task
            func: Async function to execute
            *args, **kwargs: Arguments for the function
            
        Returns:
            TaskResult with execution details
        """
        start_time = time.time()
        
        async with self.semaphore:
            try:
                self.logger.debug(f"Starting task: {task_name}")
                
                # Execute with timeout
                data = await asyncio.wait_for(
                    func(*args, **kwargs),
                    timeout=self.timeout
                )
                
                duration = time.time() - start_time
                self.logger.info(f"Task {task_name} completed in {duration:.2f}s")
                
                return TaskResult(
                    task_name=task_name,
                    success=True,
                    data=data,
                    error=None,
                    duration=duration
                )
                
            except asyncio.TimeoutError:
                duration = time.time() - start_time
                error_msg = f"Task {task_name} timed out after {self.timeout}s"
                self.logger.warning(error_msg)
                
                return TaskResult(
                    task_name=task_name,
                    success=False,
                    data=None,
                    error=error_msg,
                    duration=duration
                )
                
            except Exception as e:
                duration = time.time() - start_time
                error_msg = f"Task {task_name} failed: {str(e)}"
                self.logger.error(error_msg, exc_info=True)
                
                return TaskResult(
                    task_name=task_name,
                    success=False,
                    data=None,
                    error=error_msg,
                    duration=duration
                )
    
    async def execute_all(
        self,
        tasks: List[tuple]
    ) -> List[TaskResult]:
        """
        Execute multiple tasks in parallel.
        
        Args:
            tasks: List of (task_name, func, args, kwargs) tuples
            
        Returns:
            List of TaskResults
        """
        self.logger.info(f"Executing {len(tasks)} tasks in parallel (max {self.max_concurrent} concurrent)")
        
        # Create task coroutines
        coroutines = []
        for task_info in tasks:
            if len(task_info) == 2:
                task_name, func = task_info
                args, kwargs = (), {}
            elif len(task_info) == 3:
                task_name, func, args = task_info
                kwargs = {}
            else:
                task_name, func, args, kwargs = task_info
            
            coroutines.append(
                self.execute_task(task_name, func, *args, **kwargs)
            )
        
        # Execute all tasks
        results = await asyncio.gather(*coroutines, return_exceptions=False)
        
        # Log summary
        successful = sum(1 for r in results if r.success)
        failed = len(results) - successful
        total_duration = max(r.duration for r in results) if results else 0
        
        self.logger.info(
            f"Completed {len(results)} tasks in {total_duration:.2f}s "
            f"({successful} successful, {failed} failed)"
        )
        
        return results


class RateLimiter:
    """Rate limiter for API calls"""
    
    def __init__(self, calls_per_minute: int):
        """
        Initialize rate limiter.
        
        Args:
            calls_per_minute: Maximum calls per minute
        """
        self.calls_per_minute = calls_per_minute
        self.min_interval = 60.0 / calls_per_minute
        self.last_call = 0
        self.lock = asyncio.Lock()
        self.logger = logging.getLogger(__name__)
    
    async def acquire(self):
        """Wait until rate limit allows next call"""
        async with self.lock:
            now = time.time()
            time_since_last = now - self.last_call
            
            if time_since_last < self.min_interval:
                wait_time = self.min_interval - time_since_last
                self.logger.debug(f"Rate limit: waiting {wait_time:.2f}s")
                await asyncio.sleep(wait_time)
            
            self.last_call = time.time()


class AsyncHTTPClient:
    """Async HTTP client with connection pooling"""
    
    def __init__(self, timeout: int = 30, max_connections: int = 100):
        """
        Initialize async HTTP client.
        
        Args:
            timeout: Request timeout in seconds
            max_connections: Maximum concurrent connections
        """
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.connector = aiohttp.TCPConnector(
            limit=max_connections,
            limit_per_host=10
        )
        self.session: Optional[aiohttp.ClientSession] = None
        self.logger = logging.getLogger(__name__)
    
    async def __aenter__(self):
        """Context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=self.timeout,
            connector=self.connector
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        if self.session:
            await self.session.close()
    
    async def get(self, url: str, headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Async GET request.
        
        Args:
            url: URL to fetch
            headers: Optional headers
            
        Returns:
            Response data
        """
        if not self.session:
            raise RuntimeError("Client not initialized. Use 'async with' context manager.")
        
        try:
            async with self.session.get(url, headers=headers) as response:
                return {
                    'status': response.status,
                    'headers': dict(response.headers),
                    'body': await response.text(),
                    'url': str(response.url)
                }
        except Exception as e:
            self.logger.error(f"HTTP GET failed for {url}: {e}")
            raise
    
    async def post(
        self,
        url: str,
        data: Optional[Dict] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Async POST request.
        
        Args:
            url: URL to post to
            data: Form data
            json: JSON data
            headers: Optional headers
            
        Returns:
            Response data
        """
        if not self.session:
            raise RuntimeError("Client not initialized. Use 'async with' context manager.")
        
        try:
            async with self.session.post(url, data=data, json=json, headers=headers) as response:
                return {
                    'status': response.status,
                    'headers': dict(response.headers),
                    'body': await response.text(),
                    'url': str(response.url)
                }
        except Exception as e:
            self.logger.error(f"HTTP POST failed for {url}: {e}")
            raise
