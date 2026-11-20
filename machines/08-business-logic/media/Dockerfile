FROM php:8.3-apache

# Intentionally vulnerable media host for uploaded "product images" / avatars.
# AddHandler (instead of FilesMatch \.php$) executes PHP whenever ".php"
# appears ANYWHERE in the filename, so double extensions like x.php.jpg run.
COPY uploads.conf /etc/apache2/conf-available/uploads.conf
RUN a2enconf uploads

EXPOSE 80