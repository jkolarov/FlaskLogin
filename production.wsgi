# production.wsgi
import sys

sys.path.insert(0,"/var/www/html/FlaskWebsite")

from main import app as application