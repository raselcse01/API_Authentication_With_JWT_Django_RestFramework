from django.forms import ValidationError
from rest_framework import serializers
from account.models import User
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

from authapi.account.utils import Util

class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
    class Meta:
        model = User
        fields = ['email','name','password','password2','tc']
        extra_kwargs={
            'password':{'write_only':True}
        }

# validation password and confirm password while registration
    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError("Password and confirm password dosen't match")
        return attrs
    
    def create(self, validate_data):
        return User.objects.create_user(**validate_data)
    
    
class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ['email', 'password']

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        field = ['id','email','name']

class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    class meta:
        field = ['password','password2']

    def validation(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError("Password and confirm password dosen't match")
        user.set_password(password)
        user.save()        
        return attrs
    
class SendPasswordResetEMailSerializer(serializers.Serializer):
       email = serializers.EmailField(max_length=255)
       class Meta:
           fields = ['email']

       def validate(self, attrs):
           email = attrs.get('email')
           if User.objects.filter(email=email).exists():
               user = User.objects.et(email = email)
               uid = urlsafe_base64_encode(force_bytes(user.id))
               print('Encoded UID', uid)
               token = PasswordResetTokenGenerator() .make_token(user)
               print('Password Reset Token', token)
               link = 'http://localhost:300/api/user/reset/'+uid+'/'+token
               print('Password Reset Link', link)
               #send email
               body = 'Click Following Link too  Reset you pass '+link
               data = {
                   'subject':'Reset your password',
                   'body':body,
                   'to_email':user.email
               }
               Util.send_email(data)
           else:
               raise ValidationError('You are not a Register User') 
           
class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    class meta:
        field = ['password','password2']

    def validation(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')
            if password != password2:
                raise serializers.ValidationError("Password and confirm password dosen't match")
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise ValidationError('Token is not valid or expired')
            user.set_password(password)
            user.save()        
            return attrs
        
        except DjangoUnicodeDecodeError as identifir:
            PasswordResetTokenGenerator().check_token(user, token)
            raise ValidationError('Token is not valid or expired')

            
           