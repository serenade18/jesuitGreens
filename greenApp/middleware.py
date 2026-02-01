import threading

_thread_locals = threading.local()

def get_current_user():
    return getattr(_thread_locals, "user", None)

class CurrentUserMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        _thread_locals.user = (
            request.user if request.user.is_authenticated else None
        )
        return self.get_response(request)
