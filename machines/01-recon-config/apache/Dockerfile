FROM httpd:2.4-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

COPY httpd.conf /usr/local/apache2/conf/httpd.conf
COPY htdocs/ /usr/local/apache2/htdocs/

RUN mkdir -p /usr/local/apache2/var /usr/local/apache2/davroot \
 && chown -R www-data:www-data /usr/local/apache2/var /usr/local/apache2/davroot /usr/local/apache2/htdocs \
 && chmod 0777 /usr/local/apache2/davroot

EXPOSE 80
CMD ["httpd", "-D", "FOREGROUND"]