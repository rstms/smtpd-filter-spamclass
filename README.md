# smtpd-filter-spamclass

smtpd filter updates 'X-Spam-Class' and 'X-Spam' headers

Reads classes config JSON file
default classes file is /etc/mail/filter_rspamd_classes.json
Scans headers and updates: 'X-Spam-Class' and 'X-Spam'
