import math
import hashlib
from typing import List, Tuple
import httpx

from app.core.config import settings


class VectorService:
    @staticmethod
    def embedding_mode() -> str:
        if settings.embeddings_semantic:
            return "semantic"
        return "offline_hash"

    @staticmethod
    def get_embedding(text: str, dim: int = 128, task_type: str = "RETRIEVAL_QUERY") -> List[float]:
        """
        Semantic embeddings when EMBEDDING_PROVIDER=gemini and GEMINI_API_KEY is set.
        EMBEDDING_PROVIDER=mock uses deterministic hash vectors and must be labeled offline/demo.
        """
        provider = (settings.EMBEDDING_PROVIDER or "mock").lower()
        if provider == "gemini":
            if not settings.GEMINI_API_KEY:
                raise RuntimeError(
                    "EMBEDDING_PROVIDER=gemini requires GEMINI_API_KEY; "
                    "set EMBEDDING_PROVIDER=mock for explicit offline/demo hash embeddings"
                )
            response = httpx.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{settings.EMBEDDING_MODEL}:embedContent",
                headers={"x-goog-api-key": settings.GEMINI_API_KEY},
                json={
                    "content": {"parts": [{"text": text}]},
                    "taskType": task_type,
                    "outputDimensionality": 768,
                },
                timeout=20.0,
            )
            if response.status_code == 429:
                raise RuntimeError("Gemini embeddings rate-limited")
            response.raise_for_status()
            values = response.json().get("embedding", {}).get("values")
            if not values:
                raise ValueError("Gemini embedding response did not include vector values")
            return values

        if provider not in {"mock", "hash", "offline"}:
            raise RuntimeError(
                f"Unknown EMBEDDING_PROVIDER={provider}. Use gemini (with API key) or mock for offline/demo mode."
            )

        text_clean = text.lower().strip()
        words = text_clean.split()
        vec = [0.0] * dim
        for w in words:
            h = int(hashlib.md5(w.encode("utf-8")).hexdigest(), 16)
            idx1 = h % dim
            idx2 = (h >> 16) % dim
            val = (h % 100) / 100.0 - 0.5
            vec[idx1] += val
            vec[idx2] += val * 0.5
        for i in range(len(text_clean) - 3):
            ngram = text_clean[i:i + 3]
            h = int(hashlib.sha256(ngram.encode("utf-8")).hexdigest(), 16)
            idx = h % dim
            vec[idx] += 0.2
        magnitude = math.sqrt(sum(v * v for v in vec))
        if magnitude == 0:
            return [0.0] * dim
        return [v / magnitude for v in vec]

    @staticmethod
    def cosine_similarity(v1: List[float], v2: List[float]) -> float:
        if not v1 or not v2 or len(v1) != len(v2):
            return 0.0
        dot = sum(a * b for a, b in zip(v1, v2))
        mag1 = math.sqrt(sum(a * a for a in v1))
        mag2 = math.sqrt(sum(b * b for b in v2))
        if mag1 == 0 or mag2 == 0:
            return 0.0
        return dot / (mag1 * mag2)

    @staticmethod
    def chunk_text(text: str, chunk_size: int = 400, overlap: int = 80) -> List[Tuple[str, str]]:
        lines = text.splitlines()
        chunks = []
        current_section = "General Overview"
        buffer = []
        buffer_len = 0

        for line in lines:
            if line.startswith("#"):
                current_section = line.lstrip("#").strip()
            buffer.append(line)
            buffer_len += len(line)

            if buffer_len >= chunk_size:
                chunk_str = "\n".join(buffer)
                chunks.append((current_section, chunk_str))
                buffer = buffer[-2:] if len(buffer) >= 2 else []
                buffer_len = sum(len(l) for l in buffer)

        if buffer:
            chunk_str = "\n".join(buffer)
            chunks.append((current_section, chunk_str))

        return chunks
