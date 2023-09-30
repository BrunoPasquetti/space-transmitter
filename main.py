import socket 
import os 
import rsa 
import datetime
import time 
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def file_open_binary (file):
    with open(file, "rb") as key_file:
        return key_file.read()

def write_encrypted_data(filename, data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())

    # Vamos salvar o nonce junto com o texto cifrado
    with open(filename, 'wb') as f_enc:
        for x in (cipher.nonce, ciphertext, tag):
            f_enc.write(x)

    print(f"Os dados foram criptografados e salvos em {filename}")

listaArquivos = []

while True :
    os.system("cls")
    print("Bem Vindo ao Space transmitter!!")
    print("Abaixo está nosso menu, digite o numero da opção que deseja escolher.")
    print("1-Deseja cadastrar uma sonda e gerar um par de chaves? ")
    print("2-Deseja enviar a chave da sonda? ")
    print("3-Deseja coletar dados da sonda? ")
    print("4-Deseja gerar a assinatura dos dados coletados? ")
    print("5-Deseja enviar para terra os dados? ")
    print("6-Deseja fechar o cadastro? ")
    try:
        opcao = int(input("Opção escolhida:"))

        if opcao <1 or opcao >6:
            print("Opção inválida. Escolha uma opção entre 1 e 6.")
            time.sleep(2)
            continue
        if opcao == 1:
            try:
                (pubkey, privkey) = rsa.newkeys(2048)
                with open("public.pem", "wb") as key_file:
                    key_file.write(pubkey.save_pkcs1("PEM"))
                with open("private.pem", "wb") as key_file:
                    key_file.write(privkey.save_pkcs1("PEM"))
                print("Chaves Criadas!")
            except Exception as e:
                print(f"Erro ao cadastrar a sonda e gerar o par de chaves: {e}")

        if opcao == 2:
                try:
                    def read_public_key(filename):
                        with open(filename,"rb") as file:
                            return file.read().decode('utf-8')
                    HOST_B = '127.0.0.1'
                    PORT_B= 5000
                    public_key = read_public_key("public.pem")
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.connect((HOST_B,PORT_B))
                        s.sendall('1'.encode()) #informamos o servidor que estamos enviando a chave
                        s.sendall(public_key.encode('utf-8'))
                        print("Chave enviada!")
                except Exception as e:
                    print(f"Erro ao coletar dados da sonda")


        if opcao == 3:
            try:
                now = datetime.datetime.now()
                data_formatada = now.strftime("%d.%m")

                local = input("Digite local: ")
                temperatura = input("DIgite a temperatura: ")
                radiAlfa = input("Digite a radiação Alfa: ")
                radiBeta = input("Digite a radiação Beta: ")
                radiGama = input ("Digite a radiação Gama: ")

                filename = f"{local}{data_formatada}.txt"  # Note que não há extensão .txt ou .enc aqui

                data = (
                    "Data: " + data_formatada + "\n"
                    "Local: " + local + "\n"
                    "Temperatura: " + temperatura + "\n"
                    "Radiação Alfa: " + radiAlfa + "\n"
                    "Radiação Beta: " + radiBeta + "\n"
                    "Radiação Gama: " + radiGama
                )
                key = get_random_bytes(16)
                write_encrypted_data(filename, data, key)
                listaArquivos.append(filename)
                print("Arquivos até agora: ", listaArquivos)
            except Exception as e:
                print(f"Erro ao coletar os dados da sonda: {e}")

        if opcao == 4:
            try:
                print(listaArquivos)
                def file_open_binary(file):
                    with open(file,"rb") as key_file:
                        return key_file.read()
                privatekey = rsa.PrivateKey.load_pkcs1(file_open_binary("private.pem"))

                for arquivo in listaArquivos:
                    data = file_open_binary(arquivo)
                    hashArquivo = rsa.compute_hash(data, "SHA-256")
                    print("Hash sha256 do arquivo", hashArquivo.hex())
                    assinatura = rsa.sign(data, privatekey, "SHA-256")

                    with open(f"assinatura_{arquivo}", "wb") as assinaturaArquivo:
                        assinaturaArquivo.write(assinatura)
            except Exception as e:
                print(f"Erro ao gerar a assinatura dos dados coletados: {e}")
                        
        if opcao == 5:
            try:
                    filename = input("Digite o nome do arquivo de dados que deseja enviar: ")
                    HOST_B = '127.0.0.1'
                    PORT_B = 5000 

                    #lendo o contéudo dos arquivos
                    with open(filename, "rb") as data_file:
                        data_content = data_file.read()

                        #usando a convensão correta para o nome do arquivo de ass.
                    with open(f"assinatura_{filename}", "rb") as signature_file:
                        signature_content = signature_file.read()

                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.connect ((HOST_B, PORT_B))

                        #enviar o tamanho dos dados 
                        s.sendall(len(data_content).to_bytes(4, byteorder='big')) 
                        s.sendall(data_content)
                        #enviar o tamanho da assinatura
                        s.sendall(len(signature_content).to_bytes(4, byteorder='big'))
                        s.sendall (signature_content)
                        print("Dados e assinatura enviados!")

                        #carregando chave pub e ass.
                    publickey = rsa.PublicKey.load_pkcs1(file_open_binary("public.pem"))
                    signature = file_open_binary(f"assinatura_{filename}")
        
                    rsa.verify(data_content, signature, publickey)
                    print("Arquivo corresponde à assinatura")
            except rsa.VerificationError:  
                print("Essa assinatura não é válida!")
            except Exception as e: 
                print(f"Erro desconhecido ao verificar a assinatura: {e}")
        if opcao == 6:
            print("Programa ecerrado!")
            break
        time.sleep(4)
    except ValueError:
        print("Por favor, insira um número valido")
        time.sleep(2)