import socket 
import threading
import rsa

HOST_A = '127.0.0.1'
PORT_A = 5000

def receive_data_and_signature(client_socket):
    data_length = int.from_bytes(client_socket.rec(4), byteorder='big')
    data = client_socket.recv(data_length)
    #Recebendo o tamanho da assinatura.
    signature_length = int.from_bytes(client_socket.recv(4), byteorder='big')
    signature = client_socket.recv(signature_length)
    # Carregando a chave publica.
    with open("public.pem", 'rb')as key_file:
        publickey = rsa.PublicKey.load_pkcs1(key_file.read())
    try:
        rsa.verify(data, signature, publickey)
        print("Arquivo corresponde à assinatura!")
    except rsa.VerificationError:
        print("Essa assinatura não é válida")
    
    client_socket.close()

def receive_key(client_socket):
    data = client_socket.recv(4096).decode('utf-8')
    if data:
        with open("public.pem", 'w') as file:
            file.write(data)
        print(f"Chave pública recebida e salva!")
    else:
        print("Nenhum dado recebido.")
    client_socket.close()

server_socket_a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket_a.bind((HOST_A, PORT_A))
server_socket_a.listen()
while True:
    print("Esperando por uma conexão...")
    client_socket_a, client_address_a = server_socket_a.accept()
    print(f"Conexão aceita de {client_address_a}")
    
    option = client_socket_a.recv(1).decode()

    if option == "1":
        receive_key(client_socket_a)
    elif option == "2":
        receive_thread = threading.Thread(target = receive_data_and_signature, args = (client_socket_a))
        receive_thread.start()