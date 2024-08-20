from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.contrib.auth import get_user_model

from .models import Upload

User = get_user_model()


def validation_error_handler(errors: dict):
    """
    Function that takes errors dictionary from the serializers and
    returns the first error of the first key.
    """
    key = list(errors.keys())[0]
    error = errors[key]

    if type(error) == list:
        message = f'{key}: {error[0]}'
    else:
        message = f'{key}: {error}'
    return message


class S3Utility:
    @staticmethod
    def upload_to_s3(file, uploaded_by):
        """
        Function to upload file to s3 or file system.
        """
        
        if settings.USE_S3:
            # Upload to s3
            upload = Upload(file=file, uploaded_by=uploaded_by)
            upload.save()
            file_url = upload.file.url

        else:
            # Upload to file system
            fs = FileSystemStorage()
            filename = fs.save(file.name, file)
            file_url = fs.url(filename)
        
        return file_url
