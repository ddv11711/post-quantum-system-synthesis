from django.urls import path
from . import views, test_views, export_views

urlpatterns = [
    path("", views.landing, name="home"),
    path("analysis/", views.index, name="analysis"),
    path("tests/", views.test_lab, name="test-lab"),
    path("api/scenario/", test_views.security_scenario, name="security-scenario"),
    path("api/graph-example/", views.graph_example, name="graph-example"),
    path("api/graph-example/file/", views.download_example, name="download-example"),
    path("api/test-scenarios/", test_views.scenario_catalog, name="test-scenarios"),
    path("api/test-scenarios/<str:scenario_id>/run/", test_views.run_scenario, name="run-test-scenario"),
    path("api/analyze/", views.analyze_upload, name="analyze-upload"),
    path("api/repair/", views.repair_model, name="repair-model"),
    path("api/export-repaired-xlsx/", export_views.export_repaired_xlsx, name="export-repaired-xlsx"),
    path("documents/import/", views.import_normative_pdfs, name="import-normative"),
    path("documents/imported/<str:filename>/", views.download_imported, name="download-imported"),
    path("documents/imported/<str:filename>/delete/", views.delete_imported_normative_pdf, name="delete-imported-normative"),
    path("documents/<str:filename>/", views.download_normative, name="download-normative"),
]
