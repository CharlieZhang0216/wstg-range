FROM httpd:2.4-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl python3 \
 && rm -rf /var/lib/apt/lists/*

COPY httpd.conf /usr/local/apache2/conf/httpd.conf
COPY htdocs/ /usr/local/apache2/htdocs/
COPY cgi-bin/ /usr/local/apache2/cgi-bin/

RUN chmod 0755 /usr/local/apache2/cgi-bin/greet.cgi \
 && mkdir -p /usr/local/apache2/htdocs/pages /usr/local/apache2/logs \
 && chown -R www-data:www-data /usr/local/apache2/htdocs /usr/local/apache2/logs \
 && chmod 0777 /usr/local/apache2/htdocs/pages

EXPOSE 80
CMD ["httpd", "-D", "FOREGROUND"]