FROM gorugoo/poodle-test-image


ENV PATH="/usr/local/curl-test/bin:${PATH}"
ENV PATH="/usr/local/nginx/sbin/nginx:${PATH}"
COPY ../conf/nginx.conf /usr/local/nginx/conf/nginx.conf

RUN chmod +x /usr/local/nginx/sbin/nginx

CMD ["sh", "-c", "python3 /root/target-nginx/python-test-server.py & /usr/local/nginx/sbin/nginx -g 'daemon off;'"]