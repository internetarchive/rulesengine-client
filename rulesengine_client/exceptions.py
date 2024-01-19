from wayback.cdxserver import BlockedException

class MalformedResponseException(Exception):
    pass

class BlockWithMessageException(BlockedException):
    error_header = (
        "BlockWithMessageException: Blocked Site Error"
        )
    def __init__(self, block_reason="unknown"):
        self.block_reason = block_reason
