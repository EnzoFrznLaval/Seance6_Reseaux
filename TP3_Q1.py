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
    parser.add_argument("-l", "--listen", dest="mode_app", action="store_true")
    parser.add_argument("-d", "--destination", dest="destination", action="store")
    parser.add_argument("-6", dest="mode_ip", action="store", default="ipv4")
    arguments = parser.parse_args()

    est_ipv6 = (arguments.mode_ip != "ipv4")
    est_serveur = arguments.mode_app

    if est_serveur:
        if arguments.destination:
            print("Erreur: Le serveur ne peut pas avoir de destination")
            sys.exit()
    elif (not arguments.destination):
        print("Erreur: Le client doit avoir une destination")
        sys.exit()
    else:
        try:
            socket.inet_aton(arguments.destination)
        except socket.error:
            print("Erreur: L'adresse IP est invalide")
            sys.exit()

    return (est_ipv6, est_serveur, arguments.port, arguments.destination)


def make_server_socket(port: int, est_ipv6: bool) -> socket.socket:
    """
    Cette fonction doit créer le socket du serveur, le lier au port
    et démarrer l’écoute.

    Si le port est invalide ou indisponible, le programme termine.
    """
    if est_ipv6:
        socket_serveur = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    else:
        socket_serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    socket_serveur.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        socket_serveur.bind(("127.0.0.1", port))
    except:
        print("Erreur: Le port " + str(port) + " inutilisable")
        socket_serveur.close()
        sys.exit()

    socket_serveur.listen(1)

    return socket_serveur


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
        socket_client.settimeout(3)
        socket_client.connect((destination, port))
        socket_client.settimeout(None)
    except:
        print("Erreur: Connexion au serveur échouée")
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
    nombre_premier = trouver_nombre_premier()

    base = entier_aleatoire(nombre_premier)

    send_msg(destination, str(nombre_premier))
    send_msg(destination, str(base))

    return (nombre_premier, base)


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
        nombre_premier = int(recv_msg(source))
    except:
        print("Erreur: Nombre premier non reçu")
        sys.exit()

    try:
        base = int(recv_msg(source))
    except:
        print("Erreur: Nombre premier non reçu")
        sys.exit()

    return (nombre_premier, base)


def generate_pub_prv_keys(modulo: int, base: int) -> Tuple[int, int]:
    """
    Cette fonction doit :
    - à l’aide du module glocrypto, générer une clé privée,
    - à l’aide du module glocrypto, générer une clé publique,
    - retourner un tuple contenant respectivement :
        1. la clé privée
        2. la clé publique
    """
    cle_privee = entier_aleatoire(modulo)
    cle_publique = exponentiation_modulaire(base, cle_privee, modulo)

    return (cle_privee, cle_publique)


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
        print("Erreur: Envoie de la clée publique échouée")
        return None

    try:
        dest_cle_publique = int(recv_msg(destination))
    except:
        print("Erreur: Envoie de la clé publique échouée")
        return None

    return dest_cle_publique


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
    socket_serveur = make_server_socket(port, est_ipv6)

    while True:
        (client_socket, client_address) = socket_serveur.accept()

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
