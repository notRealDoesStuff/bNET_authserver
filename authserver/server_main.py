import os
import socket
import time
import asyncio
import threading
import curses
import json
import sys


def clear_term():
    os.system('cls' if os.name == 'nt' else 'clear')


version = "1"
protocol = "bNET"
protocol_ver = "1"
software_ver = "3025b"
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


throbberchars = ["|", "/", "—", "\\"]

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


def draw_console_ui(stdscr, throbber_char, input_buffer):
    stdscr.clear()
    stdscr.addstr(0, 0, f'####### bNET auth v{version} ########')
    stdscr.addstr(1, 0, f'##### Protocol: {protocol} v{protocol_ver} #####')
    stdscr.addstr(2, 0, f'#  {len(clients)} Clients connected')
    runmarker = 'Server is running...' if server_running else \
        'Server is not running...'
    stdscr.addstr(3, 0, f'#  {runmarker} {throbber_char}')
    stdscr.addstr(4, 0, '')
    stdscr.addstr(5, 0, f'Status: {status}')
    stdscr.addstr(6, 0, '### log ###')
    for idx, message in enumerate(last_logmessages):
        stdscr.addstr(7 + idx, 0, f"# {message}")
    stdscr.addstr(8 + len(last_logmessages), 0, 'Input: ')
    stdscr.addstr(8 + len(last_logmessages), 7, input_buffer)
    stdscr.refresh()


def console(stdscr):
    global status

    curses.curs_set(1)  # Show the cursor
    stdscr.nodelay(1)   # Don't block on input
    stdscr.clear()

    input_buffer = ""  # Buffer to hold user input
    throbber_index = 0
    last_throbber_update = time.time()  # Track the last update time
    last_cursor_flash = time.time()
    throbber_char = None

    while True:
        current_time = time.time()

        # Update throbber every 100 milliseconds
        if current_time - last_throbber_update >= 0.1:
            throbber_char = throbberchars[throbber_index % len(throbberchars)]
            last_throbber_update = current_time
            throbber_index += 1

        # Flash the cursor every second
        if current_time - last_cursor_flash >= 1:
            curses.curs_set(1 if curses.curs_set(0) == 0 else 0)
            last_cursor_flash = current_time

        if throbber_char:
            draw_console_ui(stdscr, throbber_char, input_buffer)
        else:
            draw_console_ui(stdscr, "$", input_buffer)

        key = stdscr.getch()  # Get user input
        if key != -1:
            if key in (curses.KEY_BACKSPACE, 127, 8):  # Handle backspace
                input_buffer = input_buffer[:-1]
                curses.curs_set(1)
            elif key == 10:  # Enter key
                # Process the input (e.g., log it, execute a command, etc.)
                handle_command(input_buffer)
                input_buffer = ""  # Clear the input buffer after processing
            elif 32 <= key <= 126:  # Printable characters
                input_buffer += chr(key)  # Add character to input buffer
                curses.curs_set(1)

        # put the cursor at the end of the input line
        stdscr.move(8 + len(last_logmessages), len(input_buffer))

        time.sleep(0.01)  # Throttle the loop to avoid high CPU usage


def handle_command(command):
    global status

    if command.lower() == "help":
        log_message("Available commands: help, status")
    elif command.lower() == "status":
        log_message(f"Current status: {status}")
    elif command.lower() == "exit":
        log_message("killing server...")
        status = "Exiting..."
        sys.exit(0)
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

            log_message(f"Accepted connection from {client_address[0]}:{client_address[1]}")

            status = "Client connected"

            # Add the client socket to the clients list
            clients.append(client_socket)

            # Handle client in a separate task
            asyncio.create_task(handle_client(client_socket))

        except Exception as e:
            log_message(f"Error accepting connection: {e}")


async def handle_client(client_socket):
    global status

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

            # process requests
            if request.startswith("CHECK::"):
                check_request = request.split("::")[1]
                if check_request == "USER":
                    bID = request.split("::")[2]
                    password = request.split("::")[3]
                    log_message(f"Checking bID: {bID}")

                    # check if bID exists in the data
                    with open(default_userdata_path, 'r') as json_file:
                        data = json.load(json_file)

                    if bID in data["bNETauth_data"]["clients"]:

                        # check if password matches
                        if data["bNETauth_data"]["clients"][bID]["password"] == password:
                            response = "OK"
                        else:
                            response = "INUSE"
                    else:
                        response = "SENDDATA"

            elif request.startswith("REGISTER::"):
                bID = request.split("::")[1]
                password = request.split("::")[2]
                log_message(f"Registering bID: {bID}")

                # check if bID already exists
                with open(default_userdata_path, 'r') as json_file:
                    data = json.load(json_file)

                if bID in data["bNETauth_data"]["clients"]:
                    # if bID exists check if password matches
                    if data["bNETauth_data"]["clients"][bID]["password"] == password:
                        # set client status to online
                        data["bNETauth_data"]["clients"][bID]["data"]["status"] = "online"
                        with open(default_userdata_path, 'w') as json_file:
                            json.dump(data, json_file, indent=4)
                        response = "OK"

                else:
                    # register the new client
                    data["bNETauth_data"]["clients"][bID] = {
                        "password": password,
                        "data": {"status": "online"}
                    }
                    with open(default_userdata_path, 'w') as json_file:
                        json.dump(data, json_file, indent=4)
                    log_message(f"Registered new bID: {bID}")
                    response = "OK"
            else:
                log_message("Unknown request")
                client_socket.send("UNKNOWN".encode('utf-8'))

            if response:
                log_message(f"Sending response: {response}")
                client_socket.send(response.encode('utf-8'))

    except socket.timeout:
        log_message("Client timeout, closing connection")
    except Exception as e:
        log_message(f"Error handling client: {e}")
        clients.remove(client_socket)
    finally:
        # set the client status to offline
        try:
            with open(default_userdata_path, 'r') as json_file:
                data = json.load(json_file)

            for bID in data["bNETauth_data"]["clients"]:
                if data["bNETauth_data"]["clients"][bID]["data"]["status"] == "online":
                    data["bNETauth_data"]["clients"][bID]["data"]["status"] = "offline"

            with open(default_userdata_path, 'w') as json_file:
                json.dump(data, json_file, indent=4)
        except Exception as e:
            log_message(f"Error updating client status: {e}")

        # Close the client socket
        client_socket.send("CLOSED".encode('utf-8'))
        client_socket.close()
        clients.remove(client_socket)
        log_message("Connection socket closed")
        status = "Listening..."


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
                log_message(f'Data folder created at {os.path.abspath(default_storage_path)}')
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
