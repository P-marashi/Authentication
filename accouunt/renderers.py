from rest_framework import renderers
import json


# what is this renderer do ?
# The render method of this custom renderer is overridden to format the response in a particular way.
#  If the response data contains an ErrorDetail object
# (which represents an error in a serializer field validation),
# the render method wraps the error message inside a dictionary with the key
# errors and returns it as a JSON string.
# Otherwise, it simply returns the response data as a JSON string.
# By using this custom renderer,
# we can ensure that error messages are consistently formatted in a particular way
# across all API views and responses.

class UserRenderer(renderers.JSONRenderer):
    charset = 'utf-8'

    def render(self, data, accepted_media_type=None, renderer_context=None):
        response = ''
        if 'ErrorDetail' in str(data):
            response = json.dumps({'errors': data})
        else:
            response = json.dumps(data)
        return response
