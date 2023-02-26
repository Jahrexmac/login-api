from django.urls import path
from rest_framework_jwt.views import obtain_jwt_token, refresh_jwt_token
from .views import RegisterAPIView, ChangePasswordView, LoginView

urlpatterns = [
    path('register/', RegisterAPIView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('password/change/', ChangePasswordView.as_view(), name='change_password'),
    path('api-token-auth/', obtain_jwt_token, name='api_token_auth'),
    path('api-token-refresh/', refresh_jwt_token, name='api_token_refresh'),
]
