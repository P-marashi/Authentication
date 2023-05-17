from django.contrib.auth.hashers import make_password
from rest_framework import serializers
from django.core.validators import MaxLengthValidator, MinLengthValidator
from .models import User, UserProfile
from .utils import check_otp


class UserRegisterAPISerializer(serializers.ModelSerializer):
    mobile = serializers.CharField(max_length=11,
                                   validators=(
                                       MaxLengthValidator(11),
                                       MinLengthValidator(11)
                                   ))

    class Meta:
        model = User
        fields = ('mobile',)


class VerifyRegistrationSerializer(serializers.Serializer):
    mobile = serializers.CharField(max_length=11,
                                   validators=(
                                       MaxLengthValidator(11),
                                       MinLengthValidator(11)
                                   ))
    password = serializers.CharField(max_length=12, write_only=True, allow_null=True, allow_blank=False)
    otp = serializers.CharField(max_length=4, write_only=True, allow_null=True, allow_blank=False)

    def validate_password(self, value):
        if not len(value) > 8:
            raise serializers.ValidationError("Password length must be at least 8 characters")
        if not any(C.isupper() for C in value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter")
        return value

    def create(self, validated_data):
        check = check_otp(validated_data["mobile"], validated_data["otp"])
        if not check:
            raise serializers.ValidationError(" OTP is wrong")
        user = User.objects.get(mobile=validated_data["mobile"])
        user.password = make_password(validated_data["password"])
        user.is_active = True
        user.save()
        return user


class LoginUserSerializer(serializers.ModelSerializer):
    mobile = serializers.CharField(max_length=11,
                                   validators=[
                                       MaxLengthValidator(11),
                                       MinLengthValidator(11)]
                                   )

    class Meta:
        model = User
        fields = ["mobile", "password"]


class RestPasswordAPISerializer(serializers.Serializer):
    mobile = serializers.CharField(max_length=11,
                                   validators=(
                                       MaxLengthValidator(11),
                                       MinLengthValidator(11)
                                   ))

    class Meta:
        model = User
        fields = ('mobile',)


class ResetPasswordOTPVerifySerializer(serializers.Serializer):
    mobile = serializers.CharField(max_length=11,
                                   validators=[
                                       MaxLengthValidator(11),
                                       MinLengthValidator(11)]
                                   )
    otp = serializers.CharField(write_only=True, allow_null=True, allow_blank=False)
    password = serializers.CharField(write_only=True, allow_null=True, allow_blank=False)

    def validate_password(self, value):
        if not len(value) > 8:
            raise serializers.ValidationError("Password length must be at least 8 characters")
        if not any(c.isupper() for c in value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter")
        return value

    def create_new_password(self, validated_data):
        check = check_otp(validated_data["mobile"], validated_data["otp"])
        print(check)
        if not check:
            raise serializers.ValidationError("otp is wrong ")
        user = User.objects.get(mobile=validated_data["mobile"])
        user.password = make_password("password")
        user.save()
        return user



class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['image', 'user_name', 'last_login']
