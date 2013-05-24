caldav-push-proxy
=================

Poll CalDAV servers and use push notifications to let the FxOS Calendar app
know.

Prerequisites
-------------

Redis instance.

caldav-push-proxy has been tested with
[Radicale](http://radicale.org/user_documentation/#starting-the-client). It
works with [calendarserver](http://calendarserver.org) but at least on my
config the Calendar app is unable to perform the actual sync.

Run
---

    go install mozilla.org/caldav-push-proxy
    cp config.json-dist config.json
    # edit config.json
    ./bin/caldav-push-proxy

Further improvements
--------------------

See [issues](https://github.com/nikhilm/caldav-push-proxy/issues)

Clients should also contact the proxy once a day or so even when using push
notifications to deal with a case where the proxy loses its database and has no
way to inform clients of the error.
