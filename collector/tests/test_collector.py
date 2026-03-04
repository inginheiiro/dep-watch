"""
Tests for the retry mechanism in the collector module.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, patch

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx
from collector import _retry


class TestRetry:
    @pytest.mark.asyncio
    async def test_succeeds_first_try(self):
        fn = AsyncMock(return_value="ok")
        result = await _retry(fn, "test")
        assert result == "ok"
        assert fn.call_count == 1

    @pytest.mark.asyncio
    async def test_retries_on_timeout(self):
        fn = AsyncMock(side_effect=[httpx.TimeoutException("timeout"), "ok"])
        with patch("collector.asyncio.sleep", new_callable=AsyncMock):
            result = await _retry(fn, "test")
        assert result == "ok"
        assert fn.call_count == 2

    @pytest.mark.asyncio
    async def test_retries_on_connect_error(self):
        fn = AsyncMock(side_effect=[httpx.ConnectError("refused"), "ok"])
        with patch("collector.asyncio.sleep", new_callable=AsyncMock):
            result = await _retry(fn, "test")
        assert result == "ok"
        assert fn.call_count == 2

    @pytest.mark.asyncio
    async def test_gives_up_after_max_retries(self):
        fn = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        with patch("collector.asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises(httpx.TimeoutException):
                await _retry(fn, "test")
        assert fn.call_count == 3  # MAX_RETRIES = 3

    @pytest.mark.asyncio
    async def test_non_retryable_error_propagates(self):
        fn = AsyncMock(side_effect=ValueError("bad"))
        with pytest.raises(ValueError):
            await _retry(fn, "test")
        assert fn.call_count == 1
