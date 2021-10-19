import argparse
import socket
import sys
import math

from glocrypto import *
from glosocket import *


def get_arguments() -> Tuple[bool, bool, int, Optional[str]]:
    """
    Cette fonction doit :
    - ajouter les arguments attendus aux parser,
    - récupérer les arguments passés,
    - retourner un tuple contenant dans cet ordre : 
        1. est-ce que le protocole est IPv6 ? (Booléen)
        2. est-ce que le mode est « écoute » ? (Booléen)
        3. le port choisi (entier)
        4. l’adresse du serveur (string si client, None si serveur)
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", dest="port", type=int,
                        action="store", required=True)
    parser.add_argument("-l", "--listen", dest="appMode", action="store_true")
    parser.add_argument("-d", "--destination", dest="destination", action="store")
    parser.add_argument("-6", dest="ipMode", action="store", default="ipv4")
    arguments = parser.parse_args()

    isIpv6 = (arguments.ipMode != "ipv4")
    isServer = arguments.appMode

    if isServer:
        if arguments.destination:
            print("Error: The server cannot have a destination")
            sys.exit()
    elif (not arguments.destination):
        print("Error: The client need a destination")
        sys.exit()
    else:
        try:
            socket.inet_aton(arguments.destination)
        except socket.error:
            print("Error: The address IP is not valid")
            sys.exit()

    return (isIpv6, isServer, arguments.port, arguments.destination)


def make_server_socket(port: int, est_ipv6: bool) -> socket.socket:
    """
    Cette fonction doit créer le socket du serveur, le lier au port
    et démarrer l’écoute.

    Si le port est invalide ou indisponible, le programme termine.
    """
    if est_ipv6:
        server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    else:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind(("127.0.0.1", port))
    except:
        print("Error: Unable to bind to the port " + str(port))
        server_socket.close()
        sys.exit()

    server_socket.listen(1)

    return server_socket


def make_client_socket(destination: str, port: int, est_ipv6: bool) -> socket.socket:
    """
    Cette fonction doit créer le socket du client et le connecter au serveur.

    Si la connexion échoue, le programme termine.
    """
    if est_ipv6:
        socket_client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    else:
        socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        socket_client.connect((destination, port))
    except:
        print("Error: Can't connect to the server")
        socket_client.close()
        sys.exit()

    return socket_client


def generate_mod_base(destination: socket.socket) -> Optional[Tuple[int, int]]:
    """
    Cette fonction doit :
    - à l’aide du module glocrypto, générer le modulo et la base, 
    - à l’aide du module glosocket, transmettre à la destination
    deux messages contenant respectivement :
        1. le modulo
        2. la base
    - retourner un tuple contenant les deux valeurs dans ce même ordre.
    """
    prime_number = trouver_nombre_premier()

    base = entier_aleatoire(prime_number)

    send_msg(destination, str(prime_number))
    send_msg(destination, str(base))

    return (prime_number, base)


def fetch_mod_base(source: socket.socket) -> Tuple[int, int]:
    """
    Cette fonction doit :
    - à l’aide du module glosocket, recevoir depuis la source
    deux messages contenant respectivement :
        1. le modulo
        2. la base
    - retourner un tuple contenant les deux valeurs dans ce même ordre.

    Si l’une des réceptions échoue, le programme termine.
    """
    try:
        prime_number = int(recv_msg(source))
    except:
        print("Error: Didn't receive prime number")
        sys.exit()

    try:
        base = int(recv_msg(source))
    except:
        print("Error: Didn't receive base number")
        sys.exit()

    return (prime_number, base)


def generate_pub_prv_keys(modulo: int, base: int) -> Tuple[int, int]:
    """
    Cette fonction doit :
    - à l’aide du module glocrypto, générer une clé privée,
    - à l’aide du module glocrypto, générer une clé publique,
    - retourner un tuple contenant respectivement :
        1. la clé privée
        2. la clé publique
    """
    private_key = entier_aleatoire(modulo)
    public_key = exponentiation_modulaire(base, private_key, modulo)

    return (private_key, public_key)


def exchange_keys(destination: socket.socket, cle_pub: int) -> Optional[int]:
    """
    Cette fonction doit respectivement :
    1. à l’aide du module glosocket, envoyer sa clé publique à la destination,
    2. à l’aide du module glosocket, recevoir la clé publique de la destination

    Si l’envoi ou la réception échoue, la fonction retourne None.
    """

    try:
        send_msg(destination, str(cle_pub))
    except Exception as err:
        print("Error: Failed sending public key")
        return None

    try:
        dest_public_key = int(recv_msg(destination))
    except:
        print("Error: Failed receiving public key")
        return None

    return dest_public_key


def compute_shared_key(modulo: int, cle_prv: int, cle_pub: int) -> int:
    """
    Cette fonction doit, à l’aide du module glocrypto, déduire la clé partagée.
    """
    return exponentiation_modulaire(cle_pub, cle_prv, modulo)


def server(port: int, est_ipv6: bool) -> NoReturn:
    """
    Cette fonction constitue le point d’entrée et la boucle principale du serveur.

    Si la connexion à un client est interrompue, le serveur abandonne ce client
    et en attend un nouveau.
    """
    socket_server = make_server_socket(port, est_ipv6)

    while True:
        (client_socket, client_address) = socket_server.accept()

        mod_base = generate_mod_base(client_socket)

        keys = generate_pub_prv_keys(mod_base[0], mod_base[1])

        client_pub_key = exchange_keys(client_socket, keys[1])

        shared_key = compute_shared_key(mod_base[0], keys[0], client_pub_key)

        print(shared_key)

        """
        while True:
            message_size = 2048
            message_client = client_socket.recv(message_size).decode(encoding="utf8")
            print(message_client)
            message_server = input("Enter your message: \n")
            send_msg(client_socket, message_server)
        """
        client_socket.close()

def client(destination: str, port: int, est_ipv6: bool) -> None:
    """
    Cette fonction constitue le point d’entrée et la boucle principale du client.

    Si la connexion au serveur est interrompue, le client termine.
    """
    connection_socket = make_client_socket(destination, port, est_ipv6)

    mod_base = fetch_mod_base(connection_socket)

    keys = generate_pub_prv_keys(mod_base[0], mod_base[1])

    server_pub_key = exchange_keys(connection_socket, keys[1])

    shared_key = compute_shared_key(mod_base[0], keys[0], server_pub_key)

    print(shared_key)

    connection_socket.close()


def main() -> None:
    est_ipv6, est_serveur, port, destination = get_arguments()
    if est_serveur:
        server(port, est_ipv6)
    else:
        client(destination, port, est_ipv6)  # type: ignore[arg-type]


if __name__ == "__main__":
    main()
