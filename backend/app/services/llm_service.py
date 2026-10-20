from typing import Any, Dict, Optional
import httpx

from app.core.config import settings


class LLMService:
    @staticmethod
    def status() -> Dict[str, Any]:
        provider = (settings.LLM_PROVIDER or "mock").lower()
        configured = settings.llm_configured
        return {
            "provider": provider,
            "configured": configured,
            "used_for": "natural-language summaries only" if configured else "not used",
            "note": (
                "No LLM API key is configured. Copilot uses evidence templates and retrieved knowledge text."
                if not configured
                else f"LLM provider `{provider}` will summarize retrieved evidence. It does not train or fine-tune a model."
            ),
        }

    @classmethod
    def summarize(cls, prompt: str) -> Dict[str, Any]:
        """Return a model summary only when a provider key is configured. Never fabricates citations."""
        provider = (settings.LLM_PROVIDER or "mock").lower()
        if provider in {"mock", ""} or not settings.llm_configured:
            return {"text": None, "used": False, "provider": "none", "error": None}
        try:
            if provider == "gemini":
                return cls._gemini(prompt)
            if provider == "openai":
                return cls._openai(prompt)
            if provider == "ollama":
                return cls._ollama(prompt)
        except httpx.TimeoutException:
            return {"text": None, "used": False, "provider": provider, "error": "timeout"}
        except httpx.HTTPError as exc:
            return {"text": None, "used": False, "provider": provider, "error": f"{exc.__class__.__name__}"}
        except Exception as exc:
            return {"text": None, "used": False, "provider": provider, "error": str(exc)}
        return {"text": None, "used": False, "provider": provider, "error": "unsupported_provider"}

    # Aliases tried only when the configured model name is not available to the key.
    # Google retires/renames Gemini models over time; these are tried in order so a
    # stale model name (404) or a transient capacity spike (503/ timeout) does not break summaries.
    GEMINI_MODEL_FALLBACKS = ("gemini-3.5-flash", "gemini-flash-latest")

    @classmethod
    def _gemini(cls, prompt: str) -> Dict[str, Any]:
        models = [settings.GEMINI_MODEL] + [
            m for m in cls.GEMINI_MODEL_FALLBACKS if m != settings.GEMINI_MODEL
        ]
        last_error = "model_unavailable"
        for model in models:
            result = cls._gemini_request(model, prompt)
            # Retry with the next alias on a retired model (404/400), a capacity spike (503),
            # or a hung endpoint (timeout) so one bad alias cannot disable summaries.
            if result.get("used") or result.get("error") not in {"model_unavailable", "invalid_request", "timeout"}:
                return result
            last_error = result.get("error") or last_error
        return {"text": None, "used": False, "provider": "gemini", "error": last_error}

    @staticmethod
    def _gemini_request(model: str, prompt: str) -> Dict[str, Any]:
        try:
            response = httpx.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                headers={"x-goog-api-key": settings.GEMINI_API_KEY},
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "temperature": 0.2,
                        "maxOutputTokens": 1024,
                        # Summarization needs no chain-of-thought. Thinking tokens count
                        # against maxOutputTokens, which truncated summaries mid-sentence.
                        "thinkingConfig": {"thinkingBudget": 0},
                    },
                },
                timeout=settings.LLM_TIMEOUT_SECONDS,
            )
        except httpx.TimeoutException:
            return {"text": None, "used": False, "provider": "gemini", "error": "timeout"}
        if response.status_code == 429:
            return {"text": None, "used": False, "provider": "gemini", "error": "rate_limited"}
        # 400/404 = bad/retired model name; 503 = transient capacity spike. Both are retried on another alias.
        if response.status_code in (400, 404, 503):
            return {"text": None, "used": False, "provider": "gemini", "error": "model_unavailable"}
        response.raise_for_status()
        data = response.json()
        candidates = data.get("candidates") or []
        if not candidates:
            return {"text": None, "used": False, "provider": "gemini", "error": "empty_response"}
        parts = (candidates[0].get("content") or {}).get("parts") or []
        text = "".join(p.get("text", "") for p in parts).strip()
        if not text:
            return {"text": None, "used": False, "provider": "gemini", "error": "empty_response"}
        return {"text": text[:4000], "used": True, "provider": "gemini", "error": None}

    @staticmethod
    def _openai(prompt: str) -> Dict[str, Any]:
        response = httpx.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {settings.OPENAI_API_KEY}"},
            json={
                "model": settings.OPENAI_MODEL,
                "messages": [
                    {
                        "role": "system",
                        "content": "Summarize SOC evidence. Do not invent citations, IOCs, or ATT&CK IDs not present in the prompt.",
                    },
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.2,
                "max_tokens": 512,
            },
            timeout=settings.LLM_TIMEOUT_SECONDS,
        )
        if response.status_code == 429:
            return {"text": None, "used": False, "provider": "openai", "error": "rate_limited"}
        response.raise_for_status()
        text = (((response.json().get("choices") or [{}])[0].get("message") or {}).get("content") or "").strip()
        if not text:
            return {"text": None, "used": False, "provider": "openai", "error": "empty_response"}
        return {"text": text[:4000], "used": True, "provider": "openai", "error": None}

    @staticmethod
    def _ollama(prompt: str) -> Dict[str, Any]:
        response = httpx.post(
            f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/generate",
            json={"model": settings.OPENAI_MODEL or "llama3", "prompt": prompt, "stream": False},
            timeout=settings.LLM_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        text = (response.json().get("response") or "").strip()
        if not text:
            return {"text": None, "used": False, "provider": "ollama", "error": "empty_response"}
        return {"text": text[:4000], "used": True, "provider": "ollama", "error": None}
