from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

def encrypt_aes(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """
    Criptografa o texto usando AES no modo CBC.

    :param key: Chave de criptografia de 16, 24 ou 32 bytes.
    :param iv: Vetor de inicialização de 16 bytes.
    :param plaintext: Texto em claro a ser criptografado.
    :return: Texto cifrado.
    """
    # Criação do cifrador AES no modo CBC
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )

    # Criando o objeto de criptografia
    encryptor = cipher.encryptor()

    # Preenchimento do texto em claro para ajustar ao tamanho do bloco
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Criptografando o texto em claro
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return ciphertext

def decrypt_aes(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Descriptografa o texto cifrado usando AES no modo CBC.

    :param key: Chave de criptografia de 16, 24 ou 32 bytes.
    :param iv: Vetor de inicialização de 16 bytes.
    :param ciphertext: Texto cifrado a ser descriptografado.
    :return: Texto em claro.
    """
    # Criação do cifrador AES no modo CBC
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )

    # Criando o objeto de descriptografia
    decryptor = cipher.decryptor()

    # Descriptografando o texto cifrado
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remoção do preenchimento
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext

def defHeader(iv):
    # Define campos
    IDENT       = b'ED'                 # 2 bytes
    VERSION     = bytes([0x01])         # 1 byte
    ALGO        = bytes([0x01])         # 1 byte (AES)
    MODE        = bytes([0x01])         # 1 byte (CBC)
    IV          = iv     # 16 bytes: 0x00..0x0F
    RESERVED    = bytes(11)             # 11 bytes de 0x00

    # Monta o header (32 bytes)
    header = bytearray()
    header += IDENT
    header += VERSION
    header += ALGO
    header += MODE
    header += IV
    header += RESERVED

    if len(header) != 32:
            raise ValueError(f"Erro ao montar cabeçalho: tamanho incorreto. Esperado 32, obtido {len(header)}")

    return bytes(header) # Retorna como bytes imutáveis

def encriptFile(nameFile, key):
    input_filepath = f'./arquivos/{nameFile}'
    output_filename = f'{nameFile}.enc'
    output_filepath = f'./arquivos_encript/{output_filename}'

    try:
        os.makedirs('./arquivos_encript', exist_ok=True)

        with open(input_filepath, 'rb') as f:
            originBinFile = f.read()

        iv = os.urandom(16) 
        enc = encrypt_aes(key, iv, originBinFile)

        with open(output_filepath, 'wb') as f:
            header = defHeader(iv)
            complete = header + enc
            f.write(complete)

        print(f"\n✅ Arquivo '{nameFile}' criptografado com sucesso para '{output_filepath}'.")

    except FileNotFoundError:
        print(f"\n❌ Erro: O arquivo de entrada '{input_filepath}' não foi encontrado.")
    except ValueError as e:
        print(f"\n❌ Erro durante a criptografia: {e}")
    except Exception as e:
        print(f"\n❌ Ocorreu um erro inesperado durante a criptografia de '{nameFile}': {e}")


def decriptFile(nameFile, key):
    input_filepath = f'./arquivos_encript/{nameFile}'

    basename = nameFile[0:len(nameFile)-4]
    output_filepath = f'./arquivos_decript/{basename}'

    print(basename)
    try:
        os.makedirs('./arquivos_decript', exist_ok=True)

        with open(input_filepath, 'rb') as f:
            header_bytes = f.read(32)

            if len(header_bytes) < 32:
                raise ValueError("Arquivo cifrado é muito pequeno para conter o cabeçalho completo.")

            ident      = header_bytes[0:2]        # 2 bytes
            version    = header_bytes[2]          # 1 byte
            algo       = header_bytes[3]          # 1 byte
            mode       = header_bytes[4]          # 1 byte
            iv         = header_bytes[5:21]       # 16 bytes
            reserved   = header_bytes[21:32]      # 11 bytes

            if ident.decode() != 'ED':
                raise ValueError(f"Identificador inválido no cabeçalho")
            if version != 1:
                raise ValueError(f"Versão inválida no cabeçalho")
            if algo != 1:
                raise ValueError(f"Algoritmo inválido no cabeçalho")
            if mode != 1:
                raise ValueError(f"Modo inválido no cabeçalho")

            if len(iv) != 16:
                 raise ValueError(f"Tamanho do IV incorreto no cabeçalho: Esperado 16, obtido {len(iv)}")

            ciphertext_content = f.read()

            if not ciphertext_content:
                print("⚠️ Aviso: O arquivo cifrado não contém conteúdo após o cabeçalho. O arquivo descriptografado será vazio.")

            decrypted_plaintext = decrypt_aes(key, iv, ciphertext_content)
            
            with open(output_filepath, 'wb') as f_out:
                f_out.write(decrypted_plaintext)

        print(f"\n✅ Arquivo '{nameFile}' descriptografado com sucesso para '{output_filepath}'.")

    except FileNotFoundError:
        print(f"\n❌ Erro: O arquivo cifrado '{input_filepath}' não foi encontrado. Certifique-se de que o arquivo .enc está em './arquivos_encript/'.")
    except ValueError as e:
        print(f"\n❌ Erro de validação ou estrutura do arquivo cifrado: {e}")
    except Exception as e:
        print(f"\n❌ Ocorreu um erro inesperado durante a descriptografia de '{nameFile}': {e}")

     
os.makedirs('./arquivos', exist_ok=True)
os.makedirs('./arquivos_encript', exist_ok=True)
os.makedirs('./arquivos_decript', exist_ok=True)
os.makedirs('./meta', exist_ok=True)

key = b'\xe1\x18\x89\xae\x98\xf7\x94\xf4+\x9bL\x89\xe0\x08W\xf8'

nameFile_input = input("Informe o nome do arquivo.\nPara criptografar: 'nome_original.txt' (deve estar em './arquivos/')\nPara descriptografar: 'nome_cifrado.enc' (deve estar em './arquivos_encript/')\nNome do arquivo: ")

op = -1
while op not in [0, 1, 2]:
    try:
        op = int(input("Qual operação ? 0 (Criptografar)\t1 (Descriptografar)\t2 (Meta)\nEscolha: "))
        if op not in [0, 1, 2]:
            print("❌ Opção inválida. Por favor, digite 0 para Criptografar ou 1 para Descriptografar.")
    except ValueError:
        print("❌ Entrada inválida. Por favor, digite um número (0 ou 1).")

print("\n--- Iniciando Operação ---")
if op == 0:
    encriptFile(nameFile_input, key)
elif op == 1:
    decriptFile(nameFile_input, key)
print("--- Operação Concluída ---\n")
