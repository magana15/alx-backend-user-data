#!/usr/bin/env python3
"""

"""


from flask import request
from typing import List,TypeVar
class Auth:
    """
    manage the api
    """


    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        checks if authentication is required
        """
        if path and not path.endswith('/'):
            path = path + '/'
        
        if not path or path not in excluded_paths:
            return True
        
        if not excluded_paths or excluded_paths == []:
            return True
        
        if path in excluded_paths:
            return False


    def authorization_header(self, request=None) -> None:
        """
        check for api
        """
        key = 'Authorization'
        if request is None or key not in request.headers:
            return
        
        return request.headers.get(key)
    
    def current_user(self, request=None) -> None:
        """return none
        """
        return
    

    

a = Auth()

print(a.require_auth(None, None))
print(a.require_auth(None, []))
print(a.require_auth("/api/v1/status/", []))
print(a.require_auth("/api/v1/status/", ["/api/v1/status/"]))
print(a.require_auth("/api/v1/status", ["/api/v1/status/"]))
print(a.require_auth("/api/v1/users", ["/api/v1/status/"]))
print(a.require_auth("/api/v1/users", ["/api/v1/status/", "/api/v1/stats"]))
