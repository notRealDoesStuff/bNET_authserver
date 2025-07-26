import os
import socket
import time
import asyncio
import threading
import curses
import json


def clear_term():
    os.system('cls' if os.name == 'nt' else 'clear')


version = "1"
protocol = "bNET"
protocol_version = "1"
software_version = "3025a"
software_name = "bNET Authentication Server"
software_author = "Bleached Development"

status = None
server_running = False

prelog_messages = []


def prelog(message):
    prelog_messages.append(message)


def show_prelog_and_exit():
    print("\n--- BLEACH PRELOG LOGGING SYSTEM ---")
    print("\nHalting due to critical error.")
    for msg in prelog_messages:
        print(msg)
    exit(1)


try:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_storage_path = os.path.join(script_dir, 'data')
    default_userdata_path = os.path.join(default_storage_path, 'users.json')
except Exception as e:
    prelog(f"Error initializing paths: {e}")
    show_prelog_and_exit()


thobberchars = ["|", "/", "-", "\\"]

try:
    with open(
        os.path.join(script_dir, 'splash.bnet'), "r", encoding="utf-8"
    ) as f:
        splash_ascii = f.read()
except Exception as e:
    splash_ascii = f"Error loading splash: {e}"


total_logged = 0
last_logmessages = []

clients = []


def log_message(message):
    global total_logged

    last_logmessages.append(f'[{total_logged}] {message}')
    total_logged += 1
    if len(last_logmessages) > 5:  # Keep only the last 5 messages
        last_logmessages.pop(0)


def splash(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(0)
    stdscr.clear()

    splash_lines = splash_ascii.split("0\n")
    try:
        height, width = stdscr.getmaxyx()
    except Exception:
        _, width = 24, 80  # Fallback to default terminal size

    for idx, line in enumerate(splash_lines):
        line = line.rstrip()
        try:
            stdscr.addstr(0 + idx, 0, line[:width-1])
        except curses.error:
            pass  # Ignore drawing errors if terminal is too small

    stdscr.refresh()
    time.sleep(1)


def console(stdscr):
    global status

    curses.curs_set(0)  # Hide the cursor
    stdscr.nodelay(1)   # Don't block on input
    stdscr.clear()

    input_buffer = ""  # Buffer to hold user input

    while True:
        if server_running:
            runmarker = 'Server is running...'
        else:
            runmarker = 'Server is not running...'

        for i in thobberchars:
            stdscr.clear()  # Clear the screen
            stdscr.addstr(0, 0, f'####### bNET auth v{version} ########')
            stdscr.addstr(
                1, 0,
                f'##### Protocol: {protocol} v{protocol_version} #####'
            )
            stdscr.addstr(2, 0, f'#  {len(clients)} Clients connected')
            stdscr.addstr(3, 0, f'#  {runmarker} {i}')
            stdscr.addstr(4, 0, '')
            stdscr.addstr(5, 0, f'Status: {status}')
            stdscr.addstr(6, 0, '### log ###')

            # Print log messages
            for idx, message in enumerate(last_logmessages):
                stdscr.addstr(7 + idx, 0, f"# {message}")

            # Display input prompt
            stdscr.addstr(8 + len(last_logmessages), 0, 'Input: ')

            # Display current input
            stdscr.addstr(8 + len(last_logmessages), 7, input_buffer)

            stdscr.refresh()  # Refresh the screen to show changes

            # Handle input
            key = stdscr.getch()  # Get user input
            if key in (curses.KEY_BACKSPACE, 127, 8):  # Handle backspace
                input_buffer = input_buffer[:-1]
            elif key == 10:  # Enter key
                # Process the input (e.g., log it, execute a command, etc.)
                handle_command(input_buffer)
                input_buffer = ""  # Clear the input buffer after processing
            elif 32 <= key <= 126:  # Printable characters
                input_buffer += chr(key)  # Add character to input buffehelpr

            time.sleep(0.1)  # Throttle the loop to avoid high CPU usage


def handle_command(command):
    global status

    if command.lower() == "help":
        log_message("Available commands: help, status")
    elif command.lower() == "status":
        log_message(f"Current status: {status}")
    else:
        log_message(f"Unknown command: {command}")

    return True  # Continue running the loop


async def run_server():
    global status
    global server_running

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_ip = "127.0.0.1"
    port = 30301

    server.bind((server_ip, port))
    server.listen(0)

    server_running = True
    log_message(f"Listening on {server_ip}:{port}")
    status = "Listening..."

    while True:
        try:
            client_socket, client_address = \
                await \
                asyncio.get_event_loop().run_in_executor(
                    None,
                    server.accept
                    )

            log_message(f"Accepted connection from {
                client_address[0]}:{client_address[1]}")

            status = "Client connected"

            # Add the client socket to the clients list
            clients.append(client_socket)

            # Handle client in a separate task
            asyncio.create_task(handle_client(client_socket))

        except Exception as e:
            log_message(f"Error accepting connection: {e}")


async def handle_client(client_socket):
    global status
    auth_expected = False

    try:
        while True:
            request = await \
                asyncio.get_event_loop().run_in_executor(
                    None, client_socket.recv, 1024)

            if not request:
                log_message("Client disconnected")
                break

            request = request.decode("utf-8")
            log_message(f"Received: {request}")

            # need to make this better
            if request.lower() == "auth":
                auth_expected = True

                response = "Please send your authentication code.".encode(
                    "utf-8")

                client_socket.send(response)
            elif auth_expected:
                log_message(f"Authentication code received: {request}")
                response = "Authentication successful.".encode("utf-8")
                client_socket.send(response)
                auth_expected = False
            else:
                response = \
                    "Unknown command. \
                    Please send 'auth' to start \
                    authentication.".encode("utf-8")

                client_socket.send(response)

    except socket.timeout:
        log_message("Client timeout, closing connection")
    except Exception as e:
        log_message(f"Error handling client: {e}")
    finally:
        client_socket.close()
        log_message("Connection to client closed")
        status = "Listening..."
        # Remove the client from the clients list
        clients.remove(client_socket)


def init():
    global status
    status = 'Initializing Console...'

    try:
        # Show splash screen first
        status = 'Showing splash screen...'
        curses.wrapper(splash)

        # Start console thread after splash
        status = 'Starting console thread...'
        console_thread = threading.Thread(
            target=lambda: curses.wrapper(console))

        console_thread.daemon = True
        console_thread.start()
    except Exception as e:
        prelog(f"CRITICAL ERROR!; {e} failed at status: {status}")
        show_prelog_and_exit()

    status = 'Initializing...'

    try:
        if not os.path.exists(default_storage_path):
            log_message('Data folder not found')
            try:
                log_message('Creating Data folder...')
                os.makedirs(default_storage_path)
            except Exception as e:
                log_message(f'Unable to make Data folder; {e}')
            finally:
                log_message(
                    f'Data folder created at {os.path.abspath(
                        default_storage_path)}')
        else:
            log_message('Data folder found')
    except Exception as e:
        log_message(f'Error while searching for Data folder; {e}')

    status = 'Searching for data json...'

    try:
        if not os.path.exists(default_userdata_path):
            log_message("Data json not found")

            default_initdata = {
                "bNETauth_data": {
                    "clients": {

                    }
                }
            }

            try:
                with open(default_userdata_path, 'w') as json_file:
                    json.dump(default_initdata, json_file, indent=4)
            except Exception as e:
                log_message(f'Unable to create Data json; {e}')
            finally:
                log_message('Data json created')
        else:
            log_message('Data json found')
    except Exception as e:
        log_message(f'Error while searching for Data json; {e}')

    status = 'Starting server session...'

    try:
        asyncio.run(run_server())
    except Exception as e:
        log_message(f'Failed to start server session; {e}')
    finally:
        log_message('Started server session')

    status = 'Initialization finished'


if __name__ == "__main__":
    init()
