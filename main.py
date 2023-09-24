import socket 
import os 
import rsa 
import datetime
import time 

def file_open_binary (file):
    with open(file, "rb") as key_file:
        return key_file.read()

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
    
    opcao = int(input("Opção escolhida:"))

    if opcao == 1:
        try:
            (pubkey, privkey) = rsa.newkeys(2048)
            with open("public.pem", "wb") as key_file:
                key_file.write(pubkey.save_pkcs1("PEM"))
            with open("private.pem", "wb") as key_file:
                key_file.write(privkey.save_pkcs1("PEM"))
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
            data_formatada = now.strftime("%d.%m") #formatação para dia e mês

            local = input("Digite local: ")
            temperatura = input("DIgite a temperatura: ")
            radiAlfa = input("Digite a radiação Alfa: ")
            radiBeta = input("Digite a radição Beta: ")
            radiGama = input ("Digite a radiação Gama: ")
            
            filename = f"{local}{data_formatada}.txt" #construindo o nome do arquivo

            listaArquivos.append(filename)
            print("Arquivos até agora: ", listaArquivos)

            with open (filename, "w") as file:
                file.write("Data: " + data_formatada + "\n")
                file.write("Local: " + local + "\n")
                file.write("Temperatura: " + temperatura + "\n")
                file.write("Radiação Alfa: " + radiAlfa + "\n")
                file.write("Radiação Beta: " + radiBeta + "\n")
                file.write("Radiação Gama: " + radiGama + "\n")
            print(f"Os dados foram salvos em {filename}!")
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
        break
    time.sleep(4)
