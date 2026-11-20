FROM php:8.3-apache

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl iputils-ping \
 && rm -rf /var/lib/apt/lists/*

COPY zz-lab.ini /usr/local/etc/php/conf.d/zz-lab.ini
COPY zz-lab.conf /etc/apache2/conf-available/zz-lab.conf
COPY 000-default.conf /etc/apache2/sites-available/000-default.conf
RUN a2enconf zz-lab

COPY html/ /var/www/html/

RUN printf 'WSTG-M05{php_code_injection_and_file_inclusion}\n' > /flag.txt \
 && chmod 0644 /flag.txt \
 && chown -R www-data:www-data /var/www/html

EXPOSE 80