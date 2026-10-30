import json
import logging
import logging.handlers
import time

from vulnscope.redact import redact_text


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact_text(record.getMessage()),
        }
        extra = getattr(record, "ctx", None)
        if extra:
            payload["ctx"] = extra
        if record.exc_info:
            payload["exc"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(logs_dir, verbose=False):
    logger = logging.getLogger("vulnscope")
    if getattr(logger, "_vs_ready", False):
        return logger
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler = logging.handlers.RotatingFileHandler(
        str(logs_dir / "vulnscope.jsonl"), maxBytes=2_000_000, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger._vs_ready = True
    return logger
