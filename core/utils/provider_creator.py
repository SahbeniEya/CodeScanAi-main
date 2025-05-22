"""
This module provides util methods used for initializing an AIProvider based on the user args.
"""

from core.providers.custom_ai_provider import CustomAIProvider
from core.providers.google_gemini_ai_provider import GoogleGeminiAIProvider
from core.providers.huggingface_provider import HuggingFaceProvider
from core.providers.open_ai_provider import OpenAIProvider

PROVIDERS = {
    "openai": OpenAIProvider,
    "gemini": GoogleGeminiAIProvider,
    "huggingface": HuggingFaceProvider,
    "custom": CustomAIProvider,
}

DEFAULT_MODELS = {
    "openai": "gpt-4o-mini",
    "gemini": "gemini-pro",
    "huggingface": "distilgpt2",
}


def init_provider(provider="huggingface", model=None, host=None, port=None, token=None, endpoint=None):
    """
    Initializes and returns the appropriate AI client based on the provider.

    Args:
        provider (str, optional): The AI provider to use. Defaults to "huggingface".
        model (str, optional): The model to use. Defaults to None.
        host (str, optional): The host for custom providers. Defaults to None.
        port (int, optional): The port for custom providers. Defaults to None.
        token (str, optional): The token for custom providers. Defaults to None.
        endpoint (str, optional): The endpoint for custom providers. Defaults to None.
    """
    # Default to huggingface if provider is None or empty
    if not provider:
        provider = "huggingface"

    if provider == "custom":
        client_params = {
            "model": model,
            "host": host,
            "port": port,
            "token": token,
            "endpoint": endpoint,
        }
    else:
        client_params = {
            "model": model if model else DEFAULT_MODELS[provider],
        }

    return PROVIDERS[provider](**client_params)
