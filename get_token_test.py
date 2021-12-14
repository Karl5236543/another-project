import requests
import rsa
import base64
import datetime


autorisation_url = f'https://api.ideabank.ua/autorization/AutorisationService.svc/Autorisation'


def get_content_header(**kwargs):
    return {
        "messageDate": datetime.datetime.now().strftime('%d.%m.%Y %H:%M:%S'),
        "messageId": "5e29ece0-cc86-40ae-99d7-3edc9935ffd1",
        "originator": {
            "system": "EXTERNAL"
        },
        "protocol": {
            "name": "Solantec",
            "version": "1.0"
        },
        "receiver": {
            "system": "EXTERNAL"
        },
        "responseParams": {
            "paging": {
                "page": 0,
                "pageSize": 0,
                "pagingtotalCount": 0
            },
            "threshold": 0
        },
        **kwargs,
    }


def get_content_autorisation(encrypt_password, encrypt_login, signature_password, signature_login):
    return {
        "header": get_content_header(),
        "password": base64.b64encode(encrypt_password).decode(),
        "signedPassword": [byte for byte in signature_password],
        "login": base64.b64encode(encrypt_login).decode(),
        "signedLogin": [byte for byte in signature_login],
        "id": 1,
    }


def get_token():
    login = 'login'
    password = 'password'

    # загружаем ключи
    with open('public_bank.pem', 'rb') as file:
        public_bank_key = rsa.PublicKey.load_pkcs1_openssl_pem(file.read())
    with open('private.pem', 'rb') as file:
        private_key = rsa.PrivateKey.load_pkcs1(file.read())

    # шибруем логин и пароль
    encrypt_password = rsa.encrypt(password.encode(), public_bank_key)
    encrypt_login = rsa.encrypt(login.encode(), public_bank_key)

    # создаём подписи
    signature_password = rsa.sign(encrypt_password, private_key, 'SHA-1')
    signature_login = rsa.sign(encrypt_login, private_key, 'SHA-1')

    content = get_content_autorisation(
        encrypt_password, encrypt_login, signature_password, signature_login
    )

    responce = requests.post(
        url=autorisation_url,
        json=content,
    )


if __name__ == '__main__':
    get_token()
