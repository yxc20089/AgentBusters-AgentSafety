import asyncio
import logging

from agentbeats.client import send_message

logger = logging.getLogger(__name__)


class ToolProvider:
    def __init__(self, max_retries: int = 3, base_delay: float = 2.0):
        self._context_ids = {}
        self._max_retries = max_retries
        self._base_delay = base_delay

    async def talk_to_agent(self, message: str, url: str, new_conversation: bool = False):
        """
        Communicate with another agent by sending a message and receiving their response.
        Includes retry logic with exponential backoff for transient failures.

        Args:
            message: The message to send to the agent
            url: The agent's URL endpoint
            new_conversation: If True, start fresh conversation; if False, continue existing conversation

        Returns:
            str: The agent's response message
        """
        last_error = None

        for attempt in range(self._max_retries):
            try:
                outputs = await send_message(
                    message=message,
                    base_url=url,
                    context_id=None if new_conversation else self._context_ids.get(url, None)
                )
                if outputs.get("status", "completed") != "completed":
                    raise RuntimeError(f"{url} responded with: {outputs}")
                self._context_ids[url] = outputs.get("context_id", None)
                return outputs["response"]

            except Exception as e:
                last_error = e
                error_name = type(e).__name__

                # Check if it's a retryable error (timeout, connection issues)
                retryable_errors = (
                    "ReadTimeout", "ConnectTimeout", "TimeoutError",
                    "RemoteProtocolError", "ConnectionError", "A2AClientTimeoutError"
                )
                is_retryable = any(err in error_name or err in str(type(e).__mro__) for err in retryable_errors)

                if not is_retryable:
                    # Non-retryable error, raise immediately
                    raise

                if attempt < self._max_retries - 1:
                    delay = self._base_delay * (2 ** attempt)  # Exponential backoff
                    logger.warning(
                        f"Request to {url} failed (attempt {attempt + 1}/{self._max_retries}): {error_name}. "
                        f"Retrying in {delay:.1f}s..."
                    )
                    await asyncio.sleep(delay)
                else:
                    logger.error(
                        f"Request to {url} failed after {self._max_retries} attempts: {error_name}"
                    )

        # All retries exhausted
        raise last_error

    def reset(self):
        self._context_ids = {}
