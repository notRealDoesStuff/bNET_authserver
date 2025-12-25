import os
import socket
import time
import asyncio
import threading
import curses
import json
import sys
import errno


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
throbberchars2 = ["_","—","‾"]

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


class Client:
    def __init__(self, sock, address=None):
        self.socket = sock
        try:
            self.address = address if address is not None else self.socket.getpeername()
        except OSError:
            self.address = ("unknown", 0)
        self.conn_port = None
        self.bID = None

    def __str__(self):
        return f"Client({self.address[0]}:{self.address[1]})"


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
        if current_time - last_throbber_update >= 0.35:
            throbber_char = throbberchars2[throbber_index % len(throbberchars2)]
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
        log_message("Available commands: help, status, exit, test-listpeers")
    elif command.lower() == "status":
        log_message(f"Current status: {status}")
    elif command.lower() == "exit":
        log_message("killing server...")
        status = "Exiting..."
        sys.exit(0)
    elif command.lower() == "test-listpeers":

        peers = []

        this_clientbID = "000000000000000000000000000000" # Dummy bID for testing

        try:
            with open(default_userdata_path, 'r') as json_file:
                        data = json.load(json_file)

            for bID, info in data["bNETauth_data"]["clients"].items():
                if info["data"]["status"] == "offline" and bID != this_clientbID:
                    # fake a client connection for testing
                    peer_ip = "0.0.0.0"
                    peer_port = "00000"
                    # create tuple of bID,IP,PORT
                    peer_entry = f"{bID};{peer_ip}:{peer_port}"
                    peers.append(peer_entry)

            response = "PEERS::" + "::".join(peers) if peers else "PEERS::NONE"
            log_message(f"Test LISTPEERS result: {response}")
        except Exception as e:
            log_message(f"Error reading user data: {e}")
    elif command.lower() == "clients":
        log_message(f"Connected clients: {len(clients)}")
        for c in clients:
            try:
                addr = c.socket.getpeername()
                log_message(f" - {addr[0]}:{addr[1]} conn_port: {getattr(c,'conn_port', None)} bID: {getattr(c,'bID', None)}")
            except Exception:
                log_message(f" - <disconnected client> conn_port: {getattr(c,'conn_port', None)} bID: {getattr(c,'bID', None)}")
    else:
        log_message(f"Unknown command: {command}")

    return True  # Continue running the loop




use_localhost = False

async def run_server():
    global status
    global server_running

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    if use_localhost:
        server_ip = "127.0.0.1"
    else:
        server_ip = ""  # Bind to all interfaces

    # Try to set SO_REUSEPORT if available (helps on some POSIX systems)
    try:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except Exception:
        pass

    # Attempt to bind; if the port is in use, try a small range of fallback ports
    base_port = 30301
    max_tries = 10
    bound = False
    for i in range(max_tries):
        try_port = base_port + i
        try:
            server.bind((server_ip, try_port))
            port = try_port
            bound = True
            break
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                log_message(f"Port {try_port} in use, trying next port...")
                time.sleep(0.2)
                continue
            else:
                log_message(f"Failed to bind socket: {e}")
                raise

    if not bound:
        log_message(f"Unable to bind to any port in range {base_port}-{base_port+max_tries-1}")
        raise SystemExit(1)

    server.listen(1)

    server_running = True
    log_message(f"Listening on {server.getsockname()}")
    status = "Listening..."

    while True:
        # Only try to set the console title on Windows. Calling external
        # commands while curses controls the terminal can break remote
        # terminals (PuTTY/SSH). Skip on POSIX systems.
        try:
            if os.name == 'nt':
                os.system('title bNET Auth - Status: ' + status)
        except Exception:
            pass

        try:
            client_socket, client_address = \
                await \
                asyncio.get_event_loop().run_in_executor(
                    None,
                    server.accept
                    )

            log_message(f"Accepted connection from {client_address[0]}:{client_address[1]}")

            status = "Client connected"

            # Add socket to Client class instance
            client = Client(client_socket, client_address)

            # Add the client object to the clients list
            clients.append(client)

            # Handle client in a separate task
            asyncio.create_task(handle_client(client))

        except socket.timeout:
            pass
        except Exception as e:
            log_message(f"Error accepting connection: {e}")


async def handle_client(client):
    global status
    this_clientbID = None

    try:
        while True:
            request = await \
                asyncio.get_event_loop().run_in_executor(
                    None, client.socket.recv, 1024)

            if not request:
                log_message("Client disconnected")
                break

            request = request.decode("utf-8")
            log_message(f"Received: {request}")

            # >> >> Process requests

            # Check request
            # >> Checks if a bID is registered and if the password matches
            if request.startswith("CHECK::"):
                check_request = request.split("::")[1]
                if check_request == "USER":
                    bID = request.split("::")[2]
                    password = request.split("::")[3]
                    log_message(f"Checking bID: {bID}")

                    # check if bID exists in the data
                    try:
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
                    except Exception as e:
                        log_message(f"Error reading user data: {e}")
                        response = "FAILED"

                    

            # Registration request
            # >> Registers a new client or sets existing client's status to online
            elif request.startswith("REGISTER::"):
                thisbID = request.split("::")[1]
                password = request.split("::")[2]
                c_port = request.split("::")[3]
                log_message(f"Registering bID: {thisbID}")

                # check if bID already exists
                with open(default_userdata_path, 'r') as json_file:
                    data = json.load(json_file)

                # register the existing client as online
                if thisbID in data["bNETauth_data"]["clients"]:
                    # if bID exists check if password matches
                    if data["bNETauth_data"]["clients"][thisbID]["password"] == password:
                        # set client status to online
                        data["bNETauth_data"]["clients"][thisbID]["data"]["status"] = "online"
                        with open(default_userdata_path, 'w') as json_file:
                            json.dump(data, json_file, indent=4)
                        response = "OK"

                        client.conn_port = c_port
                        client.bID = thisbID
                        this_clientbID = thisbID

                else:
                    # register the new client
                    data["bNETauth_data"]["clients"][thisbID] = {
                        "password": password,
                        "data": {"status": "online"}
                    }
                    with open(default_userdata_path, 'w') as json_file:
                        json.dump(data, json_file, indent=4)
                    log_message(f"Registered new bID: {thisbID}")
                    response = "OK"
                    client.conn_port = c_port
                    client.bID = thisbID
                    this_clientbID = thisbID


            # List peers request
            # >> Lists online clients to the requester & their connection info for p2p initiation
            elif request.startswith("LISTPEERS"):
                log_message(f"Listing peers to {client.socket.getpeername()}")

                peers = []
                response = "PEERS::NONE"

                try:
                    with open(default_userdata_path, 'r') as json_file:
                        data = json.load(json_file)

                    # compile a list of online clients excluding the requester
                    for bID, info in data["bNETauth_data"]["clients"].items():
                        if info["data"]["status"] == "online" and bID != this_clientbID:
                            # get the IP and PORT from the clients list
                            peer_ip = None
                            peer_port = None
                            peer_conn_port = None
                            for c in clients:
                                # Only consider Client instances
                                if not isinstance(c, Client):
                                    continue
                                try:
                                    # skip the requester entry
                                    if c.socket.getpeername() == client.socket.getpeername():
                                        continue
                                    # only collect IP/port when the bID matches this entry
                                    if c.bID == bID:
                                        peer_ip = c.socket.getpeername()[0]
                                        peer_port = c.socket.getpeername()[1]
                                        peer_conn_port = c.conn_port
                                        break
                                except Exception:
                                    continue

                            if peer_ip and peer_conn_port:
                                # create tuple of bID,IP,PORT
                                peer_entry = f"{bID};{peer_ip}:{peer_conn_port}"
                                peers.append(peer_entry)

                    response = "PEERS::" + "::".join(peers) if peers else "PEERS::NONE"
                except Exception as e:
                    log_message(f"Error reading user data: {e}")
                    response = "FAILED"

                log_message(f"Compiled peer list: {response}")

            # Ping request
            #
            elif request.startswith("PING"):
                response = "PONG"

            else:
                log_message("Unknown request")
                client.socket.send("UNKNOWN".encode('utf-8'))

            if response:
                log_message(f"Sending response: {response}")
                client.socket.send(response.encode('utf-8'))

    except socket.timeout:
        log_message("Client timeout, closing connection")
    except Exception as e:
        log_message(f"Error handling client: {e}")
        try:
            clients.remove(client)
        except ValueError:
            pass
    finally:
        # set the client status to offline
        try:
            with open(default_userdata_path, 'r') as json_file:
                data = json.load(json_file)

            # Mark this client offline only if we know its bID and it exists in the data
            if this_clientbID and this_clientbID in data.get("bNETauth_data", {}).get("clients", {}):
                try:
                    if data["bNETauth_data"]["clients"][this_clientbID]["data"].get("status") == "online":
                        data["bNETauth_data"]["clients"][this_clientbID]["data"]["status"] = "offline"
                except Exception:
                    # Defensive: if structure is unexpected, don't crash finalizer
                    pass

            with open(default_userdata_path, 'w') as json_file:
                json.dump(data, json_file, indent=4)
        except Exception as e:
            log_message(f"Error updating client status: {e}")

        # Close the client socket
        try:
            client.socket.send("CLOSED".encode('utf-8'))
        except Exception:
            pass
        try:
            client.socket.close()
        except Exception:
            pass
        try:
            clients.remove(client)
        except ValueError:
            pass
        log_message("Connection socket closed")
        status = "Listening..."


def init():
    global status
    status = 'Initializing Console...'

    try:
        # Show splash screen first (runs briefly on main thread)
        status = 'Showing splash screen...'
        curses.wrapper(splash)
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

    # Run the asyncio server in a separate daemon thread so the main thread
    # can safely run the curses UI. Running curses from a non-main thread
    # on many platforms (and especially remote terminals) causes crashes.
    def _server_runner():
        # Use new_event_loop + run_until_complete for compatibility with
        # Python versions that don't provide asyncio.run (pre-3.7).
        loop = None
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(run_server())
        except Exception as e:
            log_message(f'Failed to start server session; {e}')
        finally:
            if loop is not None:
                try:
                    loop.close()
                except Exception:
                    pass

    server_thread = threading.Thread(target=_server_runner, daemon=True)
    server_thread.start()

    log_message('Started server session')

    status = 'Initialization finished'

    # Start the curses console on the main thread (blocking). This keeps
    # curses in the main thread where it is supported by most terminals.
    try:
        status = 'Starting console thread...'
        curses.wrapper(console)
    except Exception as e:
        log_message(f'Console failed: {e}')


if __name__ == "__main__":
    init()
