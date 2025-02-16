from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, serializers
from django.contrib.auth import authenticate, login
from rest_framework_simplejwt.tokens import RefreshToken
import logging

logger = logging.getLogger(__name__)

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        username = serializer.validated_data['username']
        password = serializer.validated_data['password']

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            #logger.info(f"Login exitoso para el usuario: {username}")

            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            return Response({
                'message': 'Login exitoso',
                'access_token': access_token,
                'refresh_token': str(refresh),
            }, status=status.HTTP_200_OK)
        else:
            #logger.warning(f"Intento de inicio de sesión fallido para el usuario: {username}")
            return Response({'error': 'Invalid username or password'}, status=status.HTTP_400_BAD_REQUEST)