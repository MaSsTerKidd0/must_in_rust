import socket

def listen_for_udp_data(host='127.0.0.1', port=65431):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((host, port))
        print(f"Listening server started on {host}:{port} for UDP data")

        while True:
            data, addr = s.recvfrom(1024)  # buffer size is 1024 bytes
            if not data:
                break  # This might never happen as UDP is connectionless
            print(f"Received data from {addr}: {data}")

        print("Closing connection.")

if __name__ == "__main__":
    listen_for_udp_data()
