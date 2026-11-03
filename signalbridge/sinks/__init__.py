"""Sink interface. Adapters transport signals; they do not change signal fields."""


class SinkError(Exception):
    def __init__(self, message, category):
        super().__init__(message)
        self.category = category  # temporary or permanent


class Sink:
    sink_id = "base"
    required = True

    def open(self, run_context):
        self.run_context = run_context
        self.delivered = 0
        self.failed = 0
        self.status = "complete"
        self.error_category = None

    def send(self, batch):
        raise NotImplementedError

    def flush(self):
        return None

    def close(self):
        return None

    def result(self):
        return {
            "id": self.sink_id,
            "required": self.required,
            "status": self.status,
            "delivered": self.delivered,
            "failed": self.failed,
            **({"error_category": self.error_category} if self.error_category else {}),
        }
