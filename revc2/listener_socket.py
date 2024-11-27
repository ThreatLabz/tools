import socket
import struct



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
            
            data_size = 0xA  
            socket_uid = b'\x41\x41\x41\x41\x41\x41\x41\x41'
            char_p = b'p'
            char_u = b'U'
            actual_data = b'\x41\x41\x00\x01\x7F\x00\x00\x01\x05\x39'

            
            client_socket.sendall(struct.pack('<I', data_size))
            client_socket.sendall(socket_uid)
            client_socket.sendall(char_u)
            client_socket.sendall(actual_data)
            
                                   
            
            data_size_of_message = client_socket.recv(4)
            data_size_of_message = int.from_bytes(data_size_of_message, "little")
            print(f"Recieving {data_size_of_message} bytes of data")
            socket_uid = client_socket.recv(8)
            print(f"socketuid: {socket_uid} ")
            message = client_socket.recv(data_size_of_message)
            print(f"message: {message} ")
            
            data_size_of_message = client_socket.recv(4)
            data_size_of_message = int.from_bytes(data_size_of_message, "little")
            print(f"Recieving {data_size_of_message} bytes of data")
            socket_uid = client_socket.recv(8)
            print(f"socketuid: {socket_uid} ")
            message = client_socket.recv(data_size_of_message)
            print(f"message: {message} ")
            
                        
            data_size_of_message = client_socket.recv(4)
            data_size_of_message = int.from_bytes(data_size_of_message, "little")
            print(f"Recieving {data_size_of_message} bytes of data")
            socket_uid = client_socket.recv(8)
            print(f"socketuid: {socket_uid} ")
            message = client_socket.recv(data_size_of_message)
            print(f"message: {message} ")
            



        finally:
            # Clean up the connection
            client_socket.close()

if __name__ == "__main__":
    HOST = '127.0.0.1'  # Localhost
    PORT = 65432  # Arbitrary non-privileged port
    start_server(HOST, PORT)

