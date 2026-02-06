FROM httpd@sha256:d3b88ca0822f91e2dec6eb58a2ac7cfade27880926467fc63dcdbc857010b083

RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/debian.sources && \
    dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y apache2-utils python3 libssl-dev:i386

RUN useradd -m ctf 

RUN echo "flag{test}" > /home/ctf/flag && \
    chown -R root:ctf /home/ctf && \
    chmod -R 750 /home/ctf && \
    chmod 740 /home/ctf/flag && \
    rm /usr/local/apache2/cgi-bin/*

COPY ./my-httpd.conf /usr/local/apache2/conf/httpd.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY ./bin /usr/local/apache2/cgi-bin/

RUN chmod +x /usr/local/bin/entrypoint.sh && \
    mv /usr/local/apache2/cgi-bin/echo_server /home/ctf/echo_server && \
    chown -R root:ctf /home/ctf/echo_server && \
    chmod +x /home/ctf/echo_server && \
    chown 501:staff /usr/local/apache2/cgi-bin/* && \
    chmod 755 /usr/local/apache2/cgi-bin/*

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["httpd-foreground"]