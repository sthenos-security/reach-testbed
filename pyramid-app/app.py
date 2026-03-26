"""
Pyramid application — entrypoint.

Views registered via config.add_route() + config.add_view() are REACHABLE.
Views registered via @view_config but with routes wired here are REACHABLE.
Views in dead/ that have @view_config but NO matching route are NOT_REACHABLE.
"""
from wsgiref.simple_server import make_server
from pyramid.config import Configurator

from views.parse import parse_pdf_view
from views.config_loader import load_config_view, health_view

# NOTE: dead/unused_views.py has @view_config decorators but no routes added here.


def main():
    with Configurator() as config:
        # Routes — these define the URL → view mapping
        config.add_route('parse', '/api/parse')
        config.add_route('config', '/api/config')
        config.add_route('health', '/api/health')

        # Wire views to routes (REACHABLE)
        config.add_view(parse_pdf_view, route_name='parse', renderer='json')
        config.add_view(load_config_view, route_name='config', renderer='json')
        config.add_view(health_view, route_name='health', renderer='json')

        # NOTE: No route added for dead views — they are NOT_REACHABLE

        app = config.make_wsgi_app()
    return app


if __name__ == '__main__':
    app = main()
    server = make_server('0.0.0.0', 8080, app)
    server.serve_forever()
