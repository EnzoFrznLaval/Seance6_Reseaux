import argparse
import socket
import sys

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
        socket_serveur = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    else:
        socket_serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    socket_serveur.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        socket_serveur.bind(("127.0.0.1", port))
    except:
        print("Error: Unable to bind to the port " + str(port))
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
    # TODO
    return


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
    # TODO
    return


def generate_pub_prv_keys(modulo: int, base: int) -> Tuple[int, int]:
    """
    Cette fonction doit :
    - à l’aide du module glocrypto, générer une clé privée,
    - à l’aide du module glocrypto, générer une clé publique,
    - retourner un tuple contenant respectivement :
        1. la clé privée
        2. la clé publique
    """
    # TODO
    return


def exchange_keys(destination: socket.socket, cle_pub: int) -> Optional[int]:
    """
    Cette fonction doit respectivement :
    1. à l’aide du module glosocket, envoyer sa clé publique à la destination,
    2. à l’aide du module glosocket, recevoir la clé publique de la destination

    Si l’envoi ou la réception échoue, la fonction retourne None.
    """
    # TODO
    return


def compute_shared_key(modulo: int, cle_prv: int, cle_pub: int) -> int:
    """
    Cette fonction doit, à l’aide du module glocrypto, déduire la clé partagée.
    """
    # TODO
    return


def server(port: int, est_ipv6: bool) -> NoReturn:
    """
    Cette fonction constitue le point d’entrée et la boucle principale du serveur.

    Si la connexion à un client est interrompue, le serveur abandonne ce client
    et en attend un nouveau.
    """
    socket_server = make_server_socket(port, est_ipv6)




    #TODO
    while True:
        (client_socket, client_address) = socket_server.accept()

        data = client_socket.recv(2048)
        if len(data) == 0:
            client_socket.close()
        else:
            pass

def client(destination: str, port: int, est_ipv6: bool) -> None:
    """
    Cette fonction constitue le point d’entrée et la boucle principale du client.

    Si la connexion au serveur est interrompue, le client termine.
    """
    client_socket = make_client_socket(destination, port, est_ipv6)




    #TODO
    while True:
        data = client_socket.recv(2048)
        if len(data) == 0:
            client_socket.close()
        else:
            pass

def main() -> None:
    est_ipv6, est_serveur, port, destination = get_arguments()
    if est_serveur:
        server(port, est_ipv6)
    else:
        client(destination, port, est_ipv6)  # type: ignore[arg-type]


if __name__ == "__main__":
    main()
