from django.urls import path
from . import views, test_views

urlpatterns = [
    path("", views.landing, name="home"),
    path("analysis/", views.index, name="analysis"),
    path("tests/", views.test_lab, name="test-lab"),
    path("api/scenario/", test_views.security_scenario, name="security-scenario"),
    path("api/test-scenarios/", test_views.scenario_catalog, name="test-scenarios"),
    path("api/test-scenarios/<str:scenario_id>/run/", test_views.run_scenario, name="run-test-scenario"),
    path("api/analyze/", views.analyze_upload, name="analyze-upload"),
    path("api/repair/", views.repair_model, name="repair-model"),
    path("documents/<str:filename>/",views.download_normative,name="download-normative"),
]
