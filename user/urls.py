from django.urls import path
from . import views
from .views import GetItems ,PostItems,GetItemsByCategory,GetLogin_AdminUser,PostCreate_AdminUser,PostLogin_AdminUser

urlpatterns = [
    path('',views.index,name='index'),
    path('login',views.login,name='login'),
    path('api',views.api,name='api'),
    path('API/v2',views.API,name='API'),
    path('API/user/<str:uname>',views.UserAPI,name='UserAPI'),
    path('profile/user/<str:uname>',views.profile,name='profile'),
    path('Contact-Us/',views.contact,name='contact'),
    path('Contact-Us/msg',views.msg,name='msg'),
    path('About-Us/',views.about,name='about'),
    path('logout',views.logout,name='logout'),
    path('api-admin/user/v2/GetItems', GetItems.as_view(), name='GetItems'),
    path('api-admin/user/v2/PostItems', PostItems.as_view(), name='PostItems'),
    path('api-admin/user/v2/GetItemsByCategory/<str:category>/', GetItemsByCategory.as_view(), name='GetItemsByCategory'),
    path('api-admin/user/v2/GetLogin_AdminUser/<str:token>/', GetLogin_AdminUser.as_view(), name='GetLogin_AdminUser'),
    path('api-admin/user/v2/PostCreate_AdminUser', PostCreate_AdminUser.as_view(), name='PostCreate_AdminUser'),
    path('api-admin/user/v2/PostLogin_AdminUser', PostLogin_AdminUser.as_view(),name='PostLogin_AdminUser'),
    
]