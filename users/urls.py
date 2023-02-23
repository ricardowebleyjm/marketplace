from django.urls import path
from users import views

from rest_framework_simplejwt.views import (
    TokenRefreshView,
)



app_name = 'users'

urlpatterns = [
    path('user/', views.home, name="home"),
    path('user/register/', views.RegisterView.as_view(), name='auth_register'),
    path('user/token/', views.MarketPlaceTokenObtainView.as_view(), name="token_obtain_pair"),
    path('user/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('user/logout/', views.LogoutView.as_view(), name='logout'),
]