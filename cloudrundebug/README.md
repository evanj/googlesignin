# Cloud Run Debug

Logs all sorts of information to try and understand how Cloud Run works.


### Observations

* At deploy time, there seems to be two instances started: one maybe to first make sure the container is "okay", which then gets stopped? The second one is started on the first HTTP request.

* At deploy, or maybe when starting a new container, it gets hit with a TON of new connections, all of which close with zero bytes. Maybe the system is trying to probe to make sure it can actually handle concurrent connections?

* Logging a message 2 seconds after the request completes seems to work.

* Instances can live for quite a while. I've seen uptimes for a single instance of 17 hours, while mostly idle.

* Startup can be slow: it takes 3-5 seconds to load a basic gunicorn server, while on my local machine it is also slow, but still like 0.5 seconds. I'm guessing they try to do something tricky with disk reads to get startup time to be as fast as possible?
