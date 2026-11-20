FROM varnish:7.6.0
COPY default.vcl /etc/varnish/default.vcl
EXPOSE 80
CMD ["varnishd", "-F", "-f", "/etc/varnish/default.vcl", "-s", "malloc,64M", "-a", ":80", "-T", "127.0.0.1:6082"]