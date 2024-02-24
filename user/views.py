from django.shortcuts import render, redirect
import requests
from django.contrib.auth.models import User, auth
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from .models import Message , Product , Category ,Admin_users
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login
from .serializers import ProductSerializer , AdminUserSerializer ,AdminUserGetSerializer
from rest_framework.authtoken.models import Token
from rest_framework import status

# Create your views here.
#this is an home page !!!
def index(request):
    for user in User.objects.all():
        Token.objects.get_or_create(user=user)
    return render(request,'Home.html')

# this is a login page !!!
def login(request):
    return render(request,'login.html')

# this is an api that used to be login !!!
def api(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = auth.authenticate(username=username,password=password)
        
        if user is not None:
            auth.login(request,user)
            token, created = Token.objects.get_or_create(user=user)
            request.session['user_token'] = token.key # this is used to store the token key of user 
            # print("Token set in session:", token.key)
            return redirect('index')
        else:
            return redirect('login')
    else:
        return render('login.html')


# this is for who want to become extra ordinary !!!
@api_view (['GET'])
def API(request ):
    msg = {
        'message':"no point is here for getting any things are you trying to do something"
    }
    
    return Response(msg)


# this is for API for my users !!!
@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def UserAPI(request, uname):
    if request.user.is_authenticated:
        if uname == request.user.username:
            msg = {
                'message': "Welcome to your own API",
                'username': request.user.username,
                'email': request.user.email,
                # Avoid sending the password in the response for security reasons
            }
            return Response(msg)
        else:
            # If the requested username does not match the authenticated user's username
            msg = {
                'message': "Unauthorized to access this resource.",
            }
            return Response(msg, status=403)  # Forbidden
    else:
        # If user is not authenticated
        msg = {
            'message': "You need to be logged in to access this resource.",
        }
        return Response(msg, status=401)  # Unauthorized


@login_required
def profile(request, uname):
    user_token = request.session.get('user_token', '') # And for getting the user token from the upper store file.
    # print("User token from session:", user_token)  # Debug print
    return render(request,'profile.html',{'user_token': user_token})

def logout(request):
    auth.logout(request)
    return redirect('/')

def contact(request):
    return render(request,'contactUs.html')

def msg(request):
    if request.method=='POST':
        firstName = request.POST['firstName']
        email = request.POST['email']
        message = request.POST['message']
        
        if firstName and email and message:
            mssg = Message.objects.create(name=firstName,email=email,message=message)
            mssg.save()
            messages.success(request, 'Your message has been sent to the admin!')
        else:
            messages.success(request, 'First fill all the blanks')
            return redirect('contact')
        return redirect('/')
        
    else:
        return redirect('contact')
    
def about(request):
    return render(request,'aboutUs.html')


# class for restFramework  !!!
class GetItems(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated] # this is use for only a restFramework 
    def get(self, request, *args, **kwargs):
        product = Product.objects.all()
        serializer = ProductSerializer(product,many = True)
        return Response(serializer.data)

# class for restFramework  !!!
class PostItems(APIView):
    authentication_classes = [TokenAuthentication] # this is use for only a restFramework
    permission_classes = [IsAuthenticated] # this is use for only a restFramework
    def post(self, request, *args, **kwargs):
        serializer = ProductSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors)
# class for restFramework  !!!
class GetItemsByCategory(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    def get(self, request, category, *args, **kwargs):
        products = Product.objects.filter(P_category__name=category)
        serializer = ProductSerializer(products, many=True)
        return Response(serializer.data)

class GetLogin_AdminUser(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    def get(self, request,token, *args, **kwargs):
        if not token:
            return Response({'error': 'Token not provided'}, status=400)
        # Retrieve Admin_users based on provided token
        admin_users = Admin_users.objects.filter(admin_token__key=token)
        if not admin_users.exists():
            return Response({'error': 'Invalid token'}, status=401)
        serializer = AdminUserGetSerializer(admin_users, many=True)
        return Response(serializer.data)
    
# class for restFramework  !!!
class PostCreate_AdminUser(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        # Retrieve the authenticated user based on the token
        user = request.user

        # Check if the email already exists
        email = request.data.get('A_email')
        username = request.data.get('A_username')
        if Admin_users.objects.filter(A_email=email).exists() or Admin_users.objects.filter(A_username=username).exists():
            return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)

        # Create an AdminUser instance and set the admin_token
        serializer = AdminUserSerializer(data=request.data)
        if serializer.is_valid():
            # Set the admin_token field based on the authenticated user's token
            admin_token, created = Token.objects.get_or_create(user=user)
            serializer.save(admin_token=admin_token)  # Save the admin_token along with other fields
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class PostLogin_AdminUser(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request, *args, **kwargs):
        email = request.data.get('A_email')
        password = request.data.get('A_password')
        user = request.user
        admin_token , created = Token.objects.get_or_create(user=user)
        # Check if an Admin_user with the given email and password exists
        admin_user_exists = Admin_users.objects.filter(A_email=email, A_password=password,admin_token=admin_token).exists()
        
        if admin_user_exists:
            return Response({'Message': 'You are logged in'}, status=status.HTTP_200_OK)
        else:
            return Response({'Message': 'Invalid email or password'}, status=status.HTTP_400_BAD_REQUEST)
    
