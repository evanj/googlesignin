#!/usr/bin/env python3
import flask
import os
import sys
import logging
import werkzeug.wrappers

_IAP_EMAIL_HEADER_ENV_KEY = 'HTTP_X_GOOG_AUTHENTICATED_USER_EMAIL'
_IAP_EMAIL_HEADER = 'X-Goog-Authenticated-User-Email'
_IAP_VALUE_PREFIX = 'accounts.google.com:'


class RequireSignInProxyMiddleware(object):
    """
    Rejects requests that do not come from the Sign-In or Google Identity-Aware Proxy.

    TODO: This should validate the cryptographic token as described below. However, this will
    ensure requests came from localhost, so that should be okay.

    https://cloud.google.com/iap/docs/signed-headers-howto
    """

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        def make_forbidden_response():
            response = werkzeug.wrappers.Response('Forbidden', status=403)
            return response(environ, start_response)

        remote_addr = environ.get('REMOTE_ADDR', '')
        if remote_addr != '127.0.0.1':
            logging.error('rejecting request that did not come from localhost: %s',
                repr(remote_addr))
            return make_forbidden_response()

        iap_email = environ.get(_IAP_EMAIL_HEADER_ENV_KEY, '')
        if not iap_email.startswith(_IAP_VALUE_PREFIX):
            logging.error('rejecting request without valid email: %s', repr(iap_email))
            return make_forbidden_response()

        logging.info('valid request from user: %s', iap_email[len(_IAP_VALUE_PREFIX):])
        return self.app(environ, start_response)


def must_get_email(request):
    '''Returns the authenticated email address or raises ValueError.'''

    iap_email = request.headers.get(_IAP_EMAIL_HEADER, '')
    if not iap_email.startswith(_IAP_VALUE_PREFIX):
        raise ValueError('not authenticated')
    return iap_email[len(_IAP_VALUE_PREFIX):]


def root_handler():
    logging.info('root handler')

    output = 'AUTHENTICATED AS: {}\n\n'.format(must_get_email(flask.request))

    output += 'REQUEST HEADERS:\n\n'
    for key, value in flask.request.headers:
        output += '{}: {}\n'.format(key, value)

    resp = flask.make_response(output)
    resp.headers['Content-Type'] = 'text/plain;charset=utf-8'
    return resp


def create_app():
    # HACK: We shouldn't mess with the Python logger outside of __main__ but there is no easy way
    # to tell gunicorn to do this: https://github.com/benoitc/gunicorn/issues/1909
    if logging.root and logging.root.level >= logging.INFO:
        logging.root.setLevel(logging.INFO)

    app = flask.Flask(__name__)
    app.add_url_rule('/', view_func=root_handler)

    # require authentication
    app.wsgi_app = RequireSignInProxyMiddleware(app.wsgi_app)
    return app


app = create_app()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logging.info('running debug flask server ...')
    app.run(debug=True)
