# /mscp/classes/loguruformatter.py

from pydantic import BaseModel


class LoguruFormatter(BaseModel):
    padding: int = 0
    log_format: str = (
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level}</level> | <level>{message}</level>"
    )
    log_format_debug: str = (
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | {name}:{function}:{line}{extra[padding]} | <level>{level}</level> | <level>{message}</level>\n{exception}"
    )

    def format_log(self, record) -> str:
        return self.log_format

    def format_log_debug(self, record) -> str:
        length = len("{name}:{function}:{line}".format(**record))
        self.padding = max(self.padding, length)

        record["extra"]["padding"] = " " * (self.padding - length)

        return self.log_format_debug
