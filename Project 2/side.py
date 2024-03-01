

def handle_err3(msg):
    """
    This method is designed to handle error 301 which is Moved Permanently: This is known as an HTTP redirect.
    The method extracts the URL from the server response and sends it back to the crawler.
    """
    # break msg into three parts - header, spacing, body

    msg = msg.partition('\r\n\r\n')

    # store only the header
    header = msg[0]
    redirect_url = ""
    # search for redirected link
    for h in header.split('\r\n'):
        if h.startswith("Location: "):
            redirect_url = h.split()[1]

    return redirect_url


def handle_error(msg):
    """
    Returns the appropriate code values indicating the type of error occurred so that it can be handled.
    Different status codes are:
    200 - everything is okay.
    301 - Moved Permanently: This is known as an HTTP redirect.
    403 - Forbidden and 404 - Not Found
    500 - Internal Server Error: Indicates that the Server could not or would not handle the request from the client.
    """
    if msg == "200":
        return 2
    elif msg == "302":
        return 2
    elif msg == "301":
        return 3
    elif msg == "403":
        return 4
    elif msg == "404":
        return 4
    elif msg == "500" or "501":
        return 5