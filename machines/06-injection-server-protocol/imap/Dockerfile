FROM alpine:3.20
RUN apk add --no-cache dovecot \
 && adduser -D -u 1000 vuser
COPY dovecot.conf /etc/dovecot/dovecot.conf
COPY seed/new/ /var/mail/vuser/Maildir/new/
RUN mkdir -p /var/mail/vuser/Maildir/cur /var/mail/vuser/Maildir/tmp \
 && chown -R 1000:1000 /var/mail/vuser \
 && mkdir -p /var/run/dovecot
EXPOSE 143
CMD ["dovecot", "-F"]