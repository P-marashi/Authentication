from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from accouunt.serializers import (ResetPasswordOTPVerifySerializer,
                                  RestPasswordAPISerializer,

                                  LoginUserSerializer,

                                  UserRegisterAPISerializer,
                                  VerifyRegistrationSerializer,
                                  UserProfileSerializer,
                                  )
from .renderers import UserRenderer
from .models import User, UserProfile
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import send_otp, check_otp


def get_token_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class UserRegisterAPIView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserRegisterAPISerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            try:
                otp = send_otp(request.data['mobile'])
                serializer.save()

            except IntegrityError:
                return Response({
                    'error': "User with this Phone Number is already exist "
                })
            cache.set(request.data["mobile"], otp, timeout=300)

            return Response(otp)


class VerifyUserRegisterAPIView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, *args, **kwargs):
        serializer = VerifyRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token = get_token_for_user(user)
        return Response({'token': token, 'msg': 'Registration Successful'},
                        status=status.HTTP_201_CREATED)


class LoginUserView(APIView):

    def post(self, request, format=None):
        serializer = LoginUserSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            mobile = serializer.data.get('mobile')
            password = serializer.data.get('password')
            try:
                user = User.objects.get(mobile=mobile)
            except ObjectDoesNotExist:
                return Response({'error': 'User not Register yet '}, status=status.HTTP_404_NOT_FOUND)
            user = authenticate(mobile=mobile, password=password)
            if user is not None:
                token = get_token_for_user(user)
                return Response({'token': token, 'msg': 'Login success'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': {'not_find_error': {' User password is not valid'}}},
                                status=status.HTTP_404_NOT_FOUND)


class RequestOTPAgainAPIView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserRegisterAPISerializer(data=request.data, partial=True)
        if not serializer.is_valid():
            return Response({'error': serializer.errors}, status=400)

        mobile = serializer.validated_data.get('mobile')
        try:
            otp = send_otp(mobile)
        except ValueError as e:
            return Response({'error': str(e)}, status=429)

        cache.set(mobile, otp, timeout=300)
        return Response({'success': "Your OTP is ",
                         "OTP": otp,
                         'message': 'New OTP sent to your mobile number.'
                         })


class RestPasswordAPIView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = RestPasswordAPISerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            mobile = serializer.validated_data["mobile"]
            try:
                user = User.objects.get(mobile=mobile)
            except ObjectDoesNotExist:
                return Response({'user': "User not found"})

            otp = send_otp(request.data["mobile"])
            cache.set(request.data["mobile"], otp, timeout=300)

            return Response({'success': f'OTP sent to {mobile}'
                                        f'your OTP is {otp}'},
                            status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordOTPVerify(APIView):
    """
    Verify OTP and reset password
    """
    renderer_classes = [UserRenderer]

    def post(self, request, *args, **kwargs):
        serializer = ResetPasswordOTPVerifySerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            mobile = serializer.validated_data['mobile']
            otp = serializer.validated_data['otp']
            password = serializer.validated_data['password']

            check = check_otp(mobile, otp)
            try:
                user = User.objects.get(mobile=mobile)
            except ObjectDoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

            if not check:
                return Response("otp is wrong OR expired ", status=status.HTTP_400_BAD_REQUEST)

            user.password = make_password(password)
            user.save()
            token = get_token_for_user(user)
            return Response({'token': token, 'success': 'Password reset successfully'})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_profile = UserProfile.objects.get(user=request.user)
        serializer = UserProfileSerializer(user_profile)
        return Response(serializer.data)

    def post(self, request):
        serializer = UserProfileSerializer(data=request.data)

        if serializer.is_valid():
            user_profile = serializer.save(user=request.user)
            response_data = UserProfileSerializer(user_profile).data
            return Response(response_data, status=201)

        return Response(serializer.errors, status=400)
