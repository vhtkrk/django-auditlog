from django.utils.functional import SimpleLazyObject

from auditlog.context import set_actor

class AuditlogMiddleware:
    """
    Middleware to couple the request's user to log items. This is accomplished by currying the
    signal receiver with the user from the request (or None if the user is not authenticated).
    """

    def __init__(self, get_response=None):
        self.get_response = get_response

    @staticmethod
    def _get_remote_addr(request):
        # In case there is no proxy, return the original address
        if not request.headers.get("X-Forwarded-For"):
            return request.META.get("REMOTE_ADDR")

        # In case of proxy, set 'original' address
        remote_addr: str = request.headers.get("X-Forwarded-For").split(",")[0]

        # Remove port number from remote_addr
        if "." in remote_addr and ":" in remote_addr:  # IPv4 with port (`x.x.x.x:x`)
            remote_addr = remote_addr.split(":")[0]
        elif "[" in remote_addr:  # IPv6 with port (`[:::]:x`)
            remote_addr = remote_addr[1:].split("]")[0]

        return remote_addr
    

    def __call__(self, request):
        remote_addr = self._get_remote_addr(request)

        # https://github.com/jazzband/django-auditlog/issues/115#issuecomment-1539262735
        # DRF populates request.user only later in the views, rather than in middleware.
        # Accessing request.user here directly would lead to user being null.
        # Wrapping the user in a lazy object here cleanly solves this
        # because it won't be accessed until the request does have the correct user set.
        user = SimpleLazyObject(lambda: getattr(request, "user", None))
        
        context = set_actor(actor=user, remote_addr=remote_addr)

        with context:
            return self.get_response(request)

