from pathlib import Path


class FalcoException(Exception):
    pass


class FalcoRulesFileContentError(Exception):
    def __init__(self, file: Path, message: str = "Wrong Falco Rules file content or format", *args):
        self.file = file
        self.message = message
        super().__init__(self.message, args)
