import math
import hashlib
from typing import List, Tuple


class VectorService:
    @staticmethod
    def get_embedding(text: str, dim: int = 128) -> List[float]:
        """
        Generates a normalized embedding vector for text.
        Supports deterministic hashing embedding for mock/offline mode,
        producing semantically relevant distances for text matching.
        """
        text_clean = text.lower().strip()
        words = text_clean.split()
        
        vec = [0.0] * dim
        for w in words:
            # Hash word into vector dimensions
            h = int(hashlib.md5(w.encode("utf-8")).hexdigest(), 16)
            idx1 = h % dim
            idx2 = (h >> 16) % dim
            val = (h % 100) / 100.0 - 0.5
            vec[idx1] += val
            vec[idx2] += val * 0.5
            
        # Add character n-gram features
        for i in range(len(text_clean) - 3):
            ngram = text_clean[i:i+3]
            h = int(hashlib.sha256(ngram.encode("utf-8")).hexdigest(), 16)
            idx = h % dim
            vec[idx] += 0.2

        # L2 normalize
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
        """
        Chunks text into sections with title/section header detection.
        Returns list of (section_title, chunk_content) tuples.
        """
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
                # Keep last lines for overlap
                buffer = buffer[-2:] if len(buffer) >= 2 else []
                buffer_len = sum(len(l) for l in buffer)

        if buffer:
            chunk_str = "\n".join(buffer)
            chunks.append((current_section, chunk_str))

        return chunks
