import urllib2


class RequestWithMethod(urllib2.Request):
    """
    Helper class to be able to easily specify the method for a urllib2.Request.

    Original version taken from "http://stackoverflow.com/a/6312600/98441"
    """
    def __init__(self, *args, **kwargs):
        self._method = kwargs.pop('method', None)
        urllib2.Request.__init__(self, *args, **kwargs)

    def get_method(self):
        return self._method if self._method else urllib2.Request.get_method(self)
