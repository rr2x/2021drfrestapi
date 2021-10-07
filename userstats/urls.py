from .views import ExpenseSummaryStats
from django.urls import path

urlpatterns = [
    path('expenses_category_data', ExpenseSummaryStats.as_view(),
         name='expense-category-summary-url')
]
