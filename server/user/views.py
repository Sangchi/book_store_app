from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import UserRegistrationSerializer, UserLoginSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from django.core.mail import send_mail
from rest_framework.reverse import reverse
from .models import Users
import jwt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from django.utils.html import format_html
from drf_yasg.utils import swagger_auto_schema
from loguru import logger


class RegisterUserView(APIView):

    '''
    API endpoint to register a new user.
    Allows a user to register with required credentials, send a verification email with a token,
    and save the user data to the database. The user remains unverified until they click on the 
    verification link sent via email.
    
    '''
    
    permission_classes = ()
    authentication_classes = ()
    @swagger_auto_schema(operation_summary="register user", request_body=UserRegistrationSerializer, responses={200: UserRegistrationSerializer})
    def post(self, request):

        '''
        POST method for logging in a user.
        Logs in the user with the provided credentials and returns a success message upon successful login.
        Returns:
            - 200 OK: When the login is successful.
            - 400 Bad Request: If the input data is invalid.
        '''

        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
    
            token = RefreshToken.for_user(user).access_token
            link = request.build_absolute_uri(reverse('verify', args=[token]))
            html_message = format_html(
                'Hi {},<br><br>'
                'Please verify your email by clicking on the link below:<br>'
                '<a href="{}">Verify Email</a><br><br>'
                'Thank you!',
                user.username,
                link
            )

            send_mail(
                'Verify your email',
                f'Use the following link to verify your email: {link}',
                settings.EMAIL_HOST_USER,
                [user.email],
                fail_silently=False,
                html_message=html_message
            )
            

            logger.info('user registered successfully!!')
            return Response({
                'message': 'User registered successfully',
                'status': 'success',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)
        
        logger.error('unexpected error occured while registerinng the user !!')
        return Response({
            'message': 'Invalid data',
            'status': 'error',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


class LoginUserView(APIView):

    '''
    API endpoint for user login.
    Allows registered users to log in with valid credentials. The user is authenticated, and a success
    message is returned along with user data upon successful login.
    
    '''

    permission_classes = ()
    authentication_classes = ()
    @swagger_auto_schema(operation_summary='login user',request_body=UserLoginSerializer,responses={200:UserLoginSerializer})
    def post(self, request):

        '''
        POST method for logging in a user.
        Logs in the user with the provided credentials and returns a success message upon successful login.
        Returns:
            - 200 OK: When the login is successful.
            - 400 Bad Request: If the input data is invalid.
        '''

        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            
            logger.info('user login syuccesfully!!')
            return Response({
                'message': 'User login successful',
                'status': 'success',
                'data': serializer.data
            }, status=status.HTTP_200_OK)
        logger.error('unexpected error occured while login the user !!')
        return Response({
            'message': 'Invalid data',
            'status': 'error',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([AllowAny])
def verify_registered_user(request, token):

    '''
    API endpoint to verify a user's email.
    Validates the token sent to the user's email upon registration. If valid and the user exists, 
    the email is marked as verified. If the token is invalid or expired, appropriate error responses 
    are returned.
    Args:
        token (str): The token provided in the email for verification.
    Returns:
        - 200 OK: When the user's email is verified successfully.
        - 400 Bad Request: If the token is expired or invalid.
        - 404 Not Found: If the user does not exist.
    
    '''
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user = Users.objects.get(id=payload["user_id"])
        if not user.is_verified:
            user.is_verified = True
            user.save()

        logger.info('email verifed succesfully !!')
        return Response({
            'message': 'Email verified successfully',
            'status': 'success'
            }, status=status.HTTP_200_OK)
    
    except jwt.ExpiredSignatureError:
        logger.error('jwt toke is expired')
        return Response({
            'message': 'Token has expired',
            'status': 'error'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    except jwt.InvalidTokenError:
        logger.error(' jwt token is invalid')
        return Response({
            'message': 'Invalid token',
            'status': 'error'
        }, status=status.HTTP_400_BAD_REQUEST)

    except Users.DoesNotExist:
        logger.warning('user deas not exist !!')
        return Response({
            'message': 'User not found',
            'status': 'error'
        }, status=status.HTTP_404_NOT_FOUND)
    
    except Exception as e:
        logger.error('unexpected error occured while verifying the user!!')
        return Response({
            'message': 'An unexpected error occurred',
            'status': 'error',
            'error': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)
