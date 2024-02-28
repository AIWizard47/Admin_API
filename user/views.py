from django.shortcuts import render, redirect
import requests
from django.contrib.auth.models import User, auth
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from .models import Message, PhoneNumber , Product , Category ,Admin_users ,Chart
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login
from .serializers import ProductSerializer , AdminUserSerializer ,AdminUserGetSerializer
from rest_framework.authtoken.models import Token
from rest_framework import status
from django.http import JsonResponse
from django.urls import reverse

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
@login_required
def UserAPI(request):
    # Define a dictionary to store API endpoints and their URLs
    categories = Category.objects.all()
    category_list = []
    for category in categories:
        category_dict = {
            'id': category.id,
            'name': category.name,
            # Add more fields if needed
        }
        category_list.append(category_dict)
        
    api_endpoints = {
        'GetItems': reverse('GetItems'),
        'PostItems': reverse('PostItems'),
        'GetItemsByCategory': reverse('GetItemsByCategory', kwargs={'category': 'your_category'}),
        'Category':category_list,
        'GetLoginUsers':reverse('GetLogin_AdminUser' , kwargs={'token':'Your_Token'}),
        'CreateUser':reverse('PostCreate_AdminUser'),
        'LoginUser':reverse('PostLogin_AdminUser'),
        'GetChart_User':reverse('GetChart_User'),
        'PostChart_user':reverse('PostChart_user'),
        # Add more API endpoints as needed
    }
    
    # Return the dictionary as JSON response
    return JsonResponse(api_endpoints)


@login_required
def profile(request, uname):
    user_token = request.session.get('user_token', '') # Get the user token from the session
    numbers = PhoneNumber.objects.filter(admin_token=user_token)
    # numbers is a queryset, you might need to extract the first object if only one is expected
    # number = numbers.first()

    # Debug print statements to check the retrieved phone numbers
    for number in numbers:
        print("Phone Number:", number.P_number)

    return render(request, 'profile.html', {'user_token': user_token, 'numbers': numbers})

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
            return Response({'error': 'Email And username already exists'}, status=status.HTTP_400_BAD_REQUEST)

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
        email = request.data.get('email')
        password = request.data.get('password')
        user = request.user
        admin_token , created = Token.objects.get_or_create(user=user)
        # Check if an Admin_user with the given email and password exists
        admin_user_exists = Admin_users.objects.filter(A_email=email, A_password=password,admin_token=admin_token).exists()
        if admin_user_exists:
            request.session['user_login'] = email
            return Response({'Message': 'You are logged in'}, status=status.HTTP_200_OK)
        else:
            return Response({'Message': 'Invalid email or password'}, status=status.HTTP_400_BAD_REQUEST)
    
class GetChart_User(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, *args, **kwargs):
        
        # ------------**-----------------#
        # Get a chart instance
        #chart = Chart.objects.get(pk=1)        

        # Add a product to the chart
        #product = Product.objects.get(pk=1)
        #chart.products.add(product)

        # Remove a product from the chart
        #chart.products.remove(product)

        # Get all products associated with the chart
        #products = chart.products.all()
        # ------------**-----------------#
        try:
            email = request.data.get('email')
            charts = Chart.objects.get(U_user__A_email=email)
            products = charts.product.all()
            data = []
            for pro in products:
                data.append({
                    'id': pro.id,
                    'name': pro.P_name,
                    'description':pro.P_description,
                    'price':pro.P_price,
                    'picture':pro.P_picture.url,
                    'quantity':pro.P_quantity,
                })
                
            return Response(data)
        except Exception:
            return Response({'message':'Enter the email first'},status=status.HTTP_400_BAD_REQUEST)
        
    
class PostChart_user(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request, *args, **kwargs):
        
        # user_login = request.session.get('user_login', '')
        try:
            email = request.data.get('email')
            id = request.data.get('id')
            if Admin_users.objects.filter(A_email=email).exists():
                chart = Chart.objects.get(U_user__A_email=email)
                product = Product.objects.get(pk=id)
                chart.product.add(product)
                return Response({'Message': 'Your product is add to cart'}, status=status.HTTP_200_OK)
            else:
                return Response({'Message': 'you are not sign in'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception:
            return Response({'Message': 'Enter email and product id first'}, status=status.HTTP_400_BAD_REQUEST)
        
        
