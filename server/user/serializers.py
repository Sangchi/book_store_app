from rest_framework import serializers
from .models import Users
import re
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken

class UserRegistrationSerializer(serializers.ModelSerializer):
    

    class Meta:
        model = Users
        fields = ['username', 'email', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate_username(self, value):
        user_regex = r'^(?=.*[A-Z]).{3,}$'
        if not isinstance(value, str):
            raise serializers.ValidationError("Username must be a string")
        if not re.match(user_regex, value):
            raise serializers.ValidationError(
                "Username must be at least 3 characters long, include at least one uppercase letter, one lowercase letter, and one number."
            )
        return value

    def validate_email(self, value):
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, value):
            raise serializers.ValidationError("Email must be a valid domain address")
        return value

    def validate_password(self, value):
        password_regex = r'^.{8,}$'
        if not re.match(password_regex, value):
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        return value

    def create(self, validated_data):
        user = Users.objects.create_user(
            username=validated_data["username"],
            email=validated_data["email"],
            password=validated_data["password"]
        )
        return user

class UserLoginSerializer(serializers.Serializer):

    email = serializers.EmailField(required=True, write_only=True)
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    access = serializers.CharField(read_only=True)
    refresh = serializers.CharField(read_only=True)
    data = serializers.DictField(read_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        user = authenticate(email=email, password=password)
        if user is None:
            raise serializers.ValidationError('Invalid email or password')

        
        token = RefreshToken.for_user(user)
        return {
            'data': {
                'id': user.id,  
                'username': user.username,
                'email': user.email,
            },
            'access': str(token.access_token),
            'refresh': str(token)
        }