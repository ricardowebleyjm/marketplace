from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework import status

from django.contrib.auth import get_user_model

from users.serializers import MarketPlaceTokenObtainPairSerializer, RegisterSerializer
from rest_framework import generics

User = get_user_model()


class MarketPlaceTokenObtainView(TokenObtainPairView):
    """Custom token """
    serializer_class = MarketPlaceTokenObtainPairSerializer
    
    
    
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def home(request):
    data = {
        "message": "welcome"
    }
    return Response(data)


    
class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer
    
class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response(data={"message":"success"}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(data={"message":"Bad request"}, status=status.HTTP_400_BAD_REQUEST)
