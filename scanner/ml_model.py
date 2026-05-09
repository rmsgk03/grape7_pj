from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


CONFIDENCE_THRESHOLD = 0.5
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MODEL_DIR = PROJECT_ROOT / "codebert_vuln_type_model"

_TOKENIZER: Any | None = None
_MODEL: Any | None = None
_ID2LABEL: dict[int, str] | None = None
_LOAD_ERROR: str | None = None


@dataclass(frozen=True)
class AiPrediction:
    status: str
    prediction: str | None = None
    raw_prediction: str | None = None
    confidence: float | None = None
    confidence_threshold: float = CONFIDENCE_THRESHOLD
    is_vulnerable: bool | None = None
    result_role: str = "AI_AUXILIARY_SIGNAL"
    guidance: str | None = None
    top_predictions: list[dict[str, float | str]] | None = None
    error: str | None = None
    model_path: str | None = None


def predict_code(source_code: str, confidence_threshold: float = CONFIDENCE_THRESHOLD) -> AiPrediction:
    loaded = _load_model()
    if loaded is not None:
        return loaded

    assert _TOKENIZER is not None
    assert _MODEL is not None
    assert _ID2LABEL is not None

    import torch

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    _MODEL.to(device)
    _MODEL.eval()

    inputs = _TOKENIZER(
        source_code,
        return_tensors="pt",
        padding="max_length",
        truncation=True,
        max_length=256,
    )
    inputs = {key: value.to(device) for key, value in inputs.items()}

    with torch.no_grad():
        outputs = _MODEL(**inputs)
        probs = torch.softmax(outputs.logits, dim=1)

    pred_id = torch.argmax(probs, dim=1).item()
    raw_prediction = _ID2LABEL[pred_id]
    confidence = probs[0][pred_id].item()

    top_predictions = [
        {"label": _ID2LABEL[idx], "confidence": round(score, 4)}
        for idx, score in enumerate(probs[0].tolist())
    ]
    top_predictions = sorted(top_predictions, key=lambda item: float(item["confidence"]), reverse=True)[:3]

    if confidence < confidence_threshold:
        return AiPrediction(
            status="ok",
            prediction="UNCERTAIN",
            raw_prediction=raw_prediction,
            confidence=round(confidence, 4),
            confidence_threshold=confidence_threshold,
            is_vulnerable=None,
            guidance=(
                "AI confidence is low. Treat this as an auxiliary signal and prioritize "
                "rule-based findings or manual review."
            ),
            top_predictions=top_predictions,
            model_path=str(_resolve_model_dir()),
        )

    return AiPrediction(
        status="ok",
        prediction=raw_prediction,
        raw_prediction=raw_prediction,
        confidence=round(confidence, 4),
        confidence_threshold=confidence_threshold,
        is_vulnerable=raw_prediction != "SAFE",
        guidance=(
            "AI prediction is confident enough to use as an auxiliary signal. "
            "Review it together with the rule-based findings."
        ),
        top_predictions=top_predictions,
        model_path=str(_resolve_model_dir()),
    )


def _load_model() -> AiPrediction | None:
    global _TOKENIZER, _MODEL, _ID2LABEL, _LOAD_ERROR

    if _TOKENIZER is not None and _MODEL is not None and _ID2LABEL is not None:
        return None
    if _LOAD_ERROR is not None:
        return AiPrediction(status="unavailable", error=_LOAD_ERROR, model_path=str(_resolve_model_dir()))

    model_dir = _resolve_model_dir()
    missing = _missing_model_files(model_dir)
    if missing:
        _LOAD_ERROR = "Missing model files: " + ", ".join(missing)
        return AiPrediction(status="unavailable", error=_LOAD_ERROR, model_path=str(model_dir))

    try:
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except ImportError:
        _LOAD_ERROR = (
            "AI packages are not installed. Run setup again so torch, transformers, "
            "and safetensors are installed."
        )
        return AiPrediction(status="unavailable", error=_LOAD_ERROR, model_path=str(model_dir))

    try:
        _TOKENIZER = AutoTokenizer.from_pretrained(model_dir, local_files_only=True)
        _MODEL = AutoModelForSequenceClassification.from_pretrained(model_dir, local_files_only=True)
        _ID2LABEL = _load_label_mapping(model_dir)
    except Exception as exc:
        _LOAD_ERROR = f"Could not load AI model: {exc}"
        return AiPrediction(status="unavailable", error=_LOAD_ERROR, model_path=str(model_dir))

    return None


def _resolve_model_dir() -> Path:
    configured = os.environ.get("CODEBERT_MODEL_DIR")
    if configured:
        return Path(configured).expanduser().resolve()

    direct = DEFAULT_MODEL_DIR
    if (direct / "config.json").exists():
        return direct

    nested = direct / "codebert_vuln_type_model"
    if (nested / "config.json").exists():
        return nested

    return direct


def _missing_model_files(model_dir: Path) -> list[str]:
    required = ["config.json", "label_mapping.json", "tokenizer.json"]
    missing = [name for name in required if not (model_dir / name).exists()]
    if not (model_dir / "model.safetensors").exists() and not (model_dir / "pytorch_model.bin").exists():
        missing.append("model.safetensors or pytorch_model.bin")
    return missing


def _load_label_mapping(model_dir: Path) -> dict[int, str]:
    label_path = model_dir / "label_mapping.json"
    data = json.loads(label_path.read_text(encoding="utf-8"))
    return {int(key): value for key, value in data["id2label"].items()}
