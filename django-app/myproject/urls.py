"""
Root URL configuration.

Routes wired here are REACHABLE.
Routes NOT wired here (dead_app) are NOT_REACHABLE.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from myproject.api.viewsets import UserViewSet
from myproject.api import views

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')

urlpatterns = [
    # FBV — function-based view (REACHABLE)
    path('api/parse/', views.parse_pdf),
    path('api/config/', views.load_config),
    path('api/health/', views.health),

    # DRF ViewSet (REACHABLE)
    path('api/', include(router.urls)),

    # CBV — class-based view (REACHABLE)
    path('api/search/', views.SearchView.as_view()),

    # NOTE: dead_app.views and api.dead_views are intentionally NOT routed
]
