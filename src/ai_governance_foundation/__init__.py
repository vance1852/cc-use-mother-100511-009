"""科技战略协作基础服务的服务端基础包。"""

from .exception_service import ExceptionService
from .service import DomainService

__all__ = ["DomainService", "ExceptionService"]
