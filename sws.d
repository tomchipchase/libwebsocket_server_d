import std.conv;
import std.string;
import std.stdio;
import libwebsockets;

interface WebCall {
  string opCall(string path);
}

extern (C) int callback(T : WebCall)
  (libwebsocket_context *context, libwebsocket *wsi,
   libwebsocket_callback_reasons reason, void *user, void *_in, size_t len) {
  char *requested_uri;
  T webserver = new T;

  switch (reason) {
    case libwebsocket_callback_reasons.LWS_CALLBACK_HTTP:
      requested_uri = cast(char *) _in;
      writeln("requested URI: ", to!string(requested_uri));

      string response = webserver(to!string(requested_uri));
      libwebsocket_write(wsi, cast(ubyte *)response.ptr, response.length,
          libwebsocket_write_protocol.LWS_WRITE_HTTP);

      return -1;
    default:
  }

  return 0;
}

class WebServer(T) {
  libwebsocket_context *context;
  lws_context_creation_info info;

  this(int port = 8080, int options = 0) {
    libwebsocket_protocols protocols[] = [
      { "http-only".ptr, &callback!T, 0 },
      { null, null, 0 }
    ];

    info.port = port;
    info.protocols = protocols.ptr;
    info.extensions = libwebsocket_get_internal_extensions();
    info.gid = -1;
    info.uid = -1;
    info.options = options;
    context = libwebsocket_create_context(&info);

    if (context is null) {
      throw new Exception("libwebsocket init failed");
    }
  }

  void opCall() {
    printf("starting server...\n");
    while (true) {
      libwebsocket_service(context, 50);
    }

    libwebsocket_context_destroy(context);
  }
}

class Foo : WebCall {
  string opCall(string path) {
    return "Hello, World!";
  }
}

int main() {
  auto webserver = new WebServer!Foo;
  webserver();
  return 0;
}
