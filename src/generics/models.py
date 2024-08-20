from django.db import models
from django.contrib.auth import get_user_model
from config.storage_backends import PublicMediaStorage, PrivateMediaStorage

User = get_user_model()

class Upload(models.Model):
    file = models.FileField(storage=PublicMediaStorage)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.ForeignKey(to=User, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self) -> str:
        return self.file.url

class UploadPrivate(models.Model):
    file = models.FileField(storage=PrivateMediaStorage())
    uploaded_at = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.ForeignKey(to=User, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self) -> str:
        return self.file.url
    