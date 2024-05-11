from livereload import Server

def serve(app, global_conf, **kw):
    server = Server(app)

    for file_type in kw.get("file_types", "").split(","):
        server.watch(file_type) if file_type else None

    host, port = kw.get("listen", "localhost:6543").split(":", 1)
    server.serve(host=host, port=port)
    return 0
