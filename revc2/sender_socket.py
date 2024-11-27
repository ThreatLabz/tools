import socket
import struct
import random


def start_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(1)

    print(f"Server listening on {host}:{port}")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address}")

        try:
           
            actual_data1 = b'secret_message1'
            client_socket.sendall(actual_data1)
            print(f"Sent Data1")

            actual_data2 = b'secret_message2'   
            client_socket.sendall(actual_data2)
            print(f"Sent Data2")
           

        finally:
            client_socket.close()

if __name__ == "__main__":
    HOST = '127.0.0.1'  
    PORT = 1337  
    start_server(HOST, PORT)

