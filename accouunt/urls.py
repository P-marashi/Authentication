from django.urls import path
from accouunt.views import (UserRegisterAPIView,
                            VerifyUserRegisterAPIView,
                            LoginUserView,
                            RestPasswordAPIView,
                            ResetPasswordOTPVerify,
                            RequestOTPAgainAPIView,
                            )
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

app_name = "User"
urlpatterns = [
    # these paths are for register and verify user
    path('register/', UserRegisterAPIView.as_view(), name="user_register"),
    path('verify/', VerifyUserRegisterAPIView.as_view(), name="verify_User_Registration"),
    # this path is for User login
    path("login/", LoginUserView.as_view(), name="login_user"),
    # these paths are for reset password
    path('reset/password/', RestPasswordAPIView.as_view(), name="rest_User_password"),
    path('reset/verify/', ResetPasswordOTPVerify.as_view(), name="rest_verify_password"),

    # this path is for request OTP again
    path('request/otp/', RequestOTPAgainAPIView.as_view(), name="request_another_OTP"),
    # jwt path for token obtain and token refresh
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

]
