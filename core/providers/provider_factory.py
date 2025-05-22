"""
This module provides a factory for creating AI providers.
"""

import os
import logging
from typing import Optional

# Import providers
from core.providers.huggingface_provider import HuggingFaceProvider
from core.providers.open_ai_provider import OpenAIProvider
from core.providers.google_gemini_ai_provider import GoogleGeminiAIProvider
from core.providers.custom_ai_provider import CustomAIProvider
from core.providers.base_ai_provider import BaseAIProvider

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

def init_provider(
    provider_type: str,
    model: Optional[str] = None,
    host: Optional[str] = None,
    port: Optional[int] = None,
    token: Optional[str] = None,
    endpoint: Optional[str] = None,
) -> BaseAIProvider:
    """
    Initialize an AI provider based on the specified type.

    Args:
        provider_type (str): Type of provider (openai, gemini, huggingface, custom).
        model (str, optional): Model to use. Defaults to None.
        host (str, optional): Host for custom provider. Defaults to None.
        port (int, optional): Port for custom provider. Defaults to None.
        token (str, optional): Token for custom provider. Defaults to None.
        endpoint (str, optional): Endpoint for custom provider. Defaults to None.

    Returns:
        BaseAIProvider: An initialized AI provider.

    Raises:
        ValueError: If the provider type is not supported.
    """
    # Default models for each provider
    default_models = {
        "openai": "gpt-4o-mini",
        "gemini": "gemini-pro",
        "huggingface": "mistralai/Mistral-7B-Instruct-v0.3",
        "custom": None,
    }

    # Use default model if none provided
    if model is None:
        model = default_models.get(provider_type)
        logging.info(f"Using default model for {provider_type}: {model}")

    # Initialize provider based on type
    if provider_type == "openai":
        # Check for API key
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OpenAI API key not found in environment variables.")
        return OpenAIProvider(model)
    
    elif provider_type == "gemini":
        # Check for API key
        api_key = os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("Google API key not found in environment variables.")
        return GoogleGeminiAIProvider(model)
    
    elif provider_type == "huggingface":
        # Check for API token
        api_token = os.environ.get("HUGGING_FACE_TOKEN") or os.environ.get("HF_TOKEN")
        if not api_token and "mistral" in model.lower():
            logging.warning("Hugging Face token not found in environment variables. Some models may not work properly.")
        return HuggingFaceProvider(model)
    
    elif provider_type == "custom":
        # Check for required parameters
        if not host or not port:
            raise ValueError("Host and port are required for custom provider.")
        return CustomAIProvider(host, port, token, endpoint)
    
    else:
        raise ValueError(f"Unsupported provider type: {provider_type}")
