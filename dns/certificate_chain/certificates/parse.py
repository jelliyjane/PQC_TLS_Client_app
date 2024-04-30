import os
import binascii

# 현재 디렉토리에서 PEM 및 DER 인증서 파일을 가져옵니다.
certificate_files = [file for file in os.listdir() if file.endswith('.crt') or file.endswith('.der')]

for certificate_file in certificate_files:
    if certificate_file.endswith('.crt'):
        try:
            with open(certificate_file, "r") as file:
                pem_certificate = file.read()
                print(f"PEM 형식의 인증서 {certificate_file}를 성공적으로 불러왔습니다.")
        except FileNotFoundError:
            print(f"{certificate_file} 파일을 찾을 수 없습니다.")
            pem_certificate = None

        # 만약 PEM 형식의 인증서를 성공적으로 불러왔다면, txt 파일에 저장
        if pem_certificate:
            with open(f"{os.path.splitext(certificate_file)[0]}.pem.txt", "w") as pem_file:
                pem_file.write(pem_certificate)

            print(f"PEM 형식의 인증서가 {os.path.splitext(certificate_file)[0]}.pem.txt 파일에 저장되었습니다.")

    elif certificate_file.endswith('.der'):
        try:
            with open(certificate_file, "rb") as file:
                der_certificate_data = file.read()
                print(f"DER 형식의 인증서 {certificate_file}를 성공적으로 불러왔습니다.")
        except FileNotFoundError:
            print(f"{certificate_file} 파일을 찾을 수 없습니다.")
            der_certificate_data = None

        # 만약 DER 형식의 인증서를 성공적으로 불러왔다면, 16진수로 변환하여 저장
        if der_certificate_data:
            hex_certificate = binascii.hexlify(der_certificate_data).decode('utf-8')

            # 16진수 데이터를 txt 파일에 저장
            with open(f"{os.path.splitext(certificate_file)[0]}.der.txt", "w") as der_file:
                der_file.write(hex_certificate)

            print(f"DER 형식의 인증서가 {os.path.splitext(certificate_file)[0]}.der.txt 파일에 저장되었습니다.")
