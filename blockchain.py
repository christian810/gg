from flask import Flask, request, jsonify
from datetime import datetime
import hashlib
import json
import time
import os
import random
import requests
import threading
import sys
from wallet import Wallet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


BLOCKCHAIN_FILE = f"blockchain_{sys.argv[1]}.json"  # 📌 Cada nodo tendrá su propia versión local
NODES_FILE = "nodes.json"  # Lista de nodos compartida
WALLET_DIR = "wallets"
if not os.path.exists(WALLET_DIR):
    os.makedirs(WALLET_DIR)

# Límite total de monedas y halving
MAX_SUPPLY = 21_000_000  
HALVING_BLOCKS = 10000  
INITIAL_REWARD = 5 
BASE_FEE = 0.1  # Tarifa mínima fija
DYNAMIC_FEE_RATE = 0.005  # 0.5% de la cantidad transferida
MAX_DAILY_MINING = 10000  # Límite diario de GG Coin por usuario
last_mine_time = {}  # Registra la última vez que un usuario minó

network_nodes = set()  # Lista de nodos conectados

class Blockchain:
    def __init__(self, port):
        self.port = port
        self.chain = []
        self.transactions = []
        self.current_supply = 0
        self.nodes = set() 
        self.load_blockchain()
        self.auto_register()  # ✅ Ahora se ejecuta al iniciar

         # ✅ Asegurar que mining_fund exista en la blockchain
        if self.get_balance("mining_fund") == 0 and len(self.chain) == 1:
            self.add_transaction("sistema", "mining_fund", 0)  # Solo para registrar la cuenta
            proof = self.proof_of_work(self.last_block["proof"])
            self.create_block(proof=proof, previous_hash=hashlib.sha256(str(self.last_block).encode()).hexdigest())
    '''
    def auto_register(self):
        """Registra el nodo en la red automáticamente al iniciar"""
        my_address = f"192.168.1.47:{self.port}"

        if os.path.exists(NODES_FILE):
            try:
                with open(NODES_FILE, "r") as file:
                    known_nodes = json.load(file).get("nodes", [])
            except json.JSONDecodeError:
                print("⚠️ Error al leer nodes.json, creando una nueva lista de nodos.")
                known_nodes = []
        else:
            known_nodes = []

        # 🔹 Si no hay nodos conocidos, este nodo se convierte en el primer nodo
        if not known_nodes:
            print("🌐 No se encontraron nodos en la red. Creando la red con este nodo.")
            self.nodes.add(my_address)
            self.save_nodes()
            return

        # 🔹 Intentar registrarse en la red con un nodo conocido
        for node in known_nodes:
            if node == my_address:
                continue  
            try:
                response = requests.post(f"http://{node}/register_node", json={"node": my_address}, timeout=5)
                if response.status_code == 200:
                    print(f"✅ Nodo registrado con éxito en {node}")
                    self.nodes.update(response.json().get("nodes", []))  # Obtener todos los nodos
                    self.save_nodes()
                    return
            except requests.exceptions.RequestException:
                print(f"⚠️ No se pudo conectar con {node}, intentando otro...")

        print("⚠️ No se pudo registrar automáticamente en la red.")
    '''

    def auto_register(self):
        """Registra automáticamente el nodo en la red al iniciarse"""
        my_address = f"192.168.1.47:{self.port}"  # Ajusta a tu IP correcta

        # Si no existe el archivo de nodos, este es el primer nodo
        if not os.path.exists(NODES_FILE):
            print("🌐 No se encontraron nodos en la red. Creando la red con este nodo.")
            self.nodes.add(my_address)
            self.save_nodes()
            return

        # Cargar nodos conocidos desde el archivo
        try:
            with open(NODES_FILE, "r") as file:
                known_nodes = json.load(file).get("nodes", [])
                
                # 🔹 Evitar agregar nodos duplicados o el propio nodo
                known_nodes = [node for node in known_nodes if node != my_address]
                self.nodes.update(known_nodes)
                self.save_nodes()

        except json.JSONDecodeError:
            print("⚠️ Error al leer nodes.json, creando una nueva lista de nodos.")
            known_nodes = []

        # Si el archivo existe pero no tiene nodos, este nodo es el primero
        if not known_nodes:
            print("🌐 Este es el primer nodo de la red.")
            self.nodes.add(my_address)
            self.save_nodes()
            return

        # 🔹 Si el nodo ya está registrado, no intentar nuevamente
        if my_address in known_nodes:
            print("✅ Este nodo ya está registrado en la red. No se necesita registro.")
            self.nodes.update(known_nodes)
            return

        # Intentar conectarse a otros nodos existentes
        for node in known_nodes:
            if node == my_address:
                continue  
            try:
                response = requests.post(f"http://{node}/register_node", json={"node": my_address}, timeout=5)
                if response.status_code == 200:
                    print(f"✅ Nodo registrado con éxito en {node}")
                    self.nodes.update(response.json().get("nodes", []))  # Obtener todos los nodos
                    self.save_nodes()
                    return
            except requests.exceptions.RequestException:
                print(f"⚠️ No se pudo conectar con {node}, intentando otro...")

        print("⚠️ No se pudo registrar automáticamente en la red.")

    def sync_with_network(self):
        """Sincroniza con los demás nodos y adopta la blockchain más larga"""
        longest_chain = None
        max_length = len(self.chain)
        #updated_supply = self.current_supply  # ✅ Guardamos el supply actual para compararlo
        #valid_chains = []

        if len(self.nodes) == 0:
            return  # ❌ No intentamos sincronizar si no hay nodos
        
        for node in self.nodes.copy():
            if node == f"192.168.1.47:{self.port}":
                continue  # Evita conectarse a sí mismo

            try:
                response = requests.get(f"http://{node}/get_chain", timeout=3)
                if response.status_code == 200:
                    data = response.json()
                    length = data["length"]
                    chain = data["chain"]
                    #supply = data.get("current_supply", self.current_supply)  # Sincronizar el supply

                    if length > max_length or (length == max_length and supply > updated_supply):
                        max_length = length
                        longest_chain = chain
                        updated_supply = supply  # Actualizamos el supply con el nodo más largo
            except requests.exceptions.RequestException:
                print(f"⚠️ No se pudo conectar con el nodo {node}")

        if longest_chain:
            self.chain = longest_chain
            #self.current_supply = updated_supply  # 🔄 Sincroniza el supply con la blockchain más larga
            self.save_blockchain()
            print("✅ Blockchain actualizada con la más larga disponible.")

    def update_supply_from_network(self):
        """Sincroniza el suministro total con el valor más alto disponible en la red."""
        highest_supply = self.current_supply
        for node in self.nodes.copy():
            if node == f"192.168.1.43:{self.port}":
                continue  
            try:
                response = requests.get(f"http://{node}/stats", timeout=3)
                if response.status_code == 200:
                    data = response.json()
                    supply = data.get("current_supply", self.current_supply)
                    if supply > highest_supply:
                        highest_supply = supply
            except requests.exceptions.RequestException:
                print(f"⚠️ No se pudo conectar con el nodo {node}")
        
        self.current_supply = highest_supply
        self.save_blockchain()



    def register_node(self, address):
        """Añadir un nodo a la red"""
        if address and address not in self.nodes and address != f"192.168.1.47:{self.port}":
            self.nodes.add(address)
            self.save_nodes()
            self.broadcast_new_node(address)

    def broadcast_new_node(self, new_node):
        """Informa a todos los nodos sobre un nuevo nodo en la red."""
        for node in self.nodes.copy():
            if node != new_node:
                try:
                    requests.post(f"http://{node}/register_node", json={"node": new_node}, timeout=3)
                except requests.exceptions.RequestException:
                    print(f"⚠️ No se pudo comunicar con {node}")

    def create_genesis_block(self):
        """Crea el bloque génesis si no existe"""
        print("🔄 Creando bloque génesis...")
        genesis_block = {
            'index': 1,
            'timestamp': time.time(),
            'transactions': [],
            'proof': 100,
            'previous_hash': "0"
        }
        self.chain.append(genesis_block)
        self.save_blockchain()
        print("✅ Bloque génesis creado.")

    def save_nodes(self):
        """Guarda la lista de nodos en un archivo JSON"""
        with open(NODES_FILE, "w") as file:
            json.dump({"nodes": list(self.nodes)}, file, indent=4)

    def get_user_id_from_address(self, address):
        """Busca el user_id correspondiente a una dirección de wallet."""
        for filename in os.listdir(WALLET_DIR):
            wallet_path = os.path.join(WALLET_DIR, filename)
            try:
                with open(wallet_path, "r") as file:
                    wallet_data = json.load(file)
                    if wallet_data.get("address") == address:
                        return wallet_data.get("user_id")
            except (json.JSONDecodeError, FileNotFoundError):
                print(f"⚠️ Archivo corrupto o inexistente: {wallet_path}")
                continue
        return None


    def create_block(self, proof, previous_hash):
        """Crea un nuevo bloque y lo agrega a la blockchain"""
        if not self.transactions:
            print("⚠️ No hay transacciones pendientes para incluir en el bloque.")
            return None  

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'transactions': self.transactions.copy(),
            'proof': proof,
            'previous_hash': previous_hash
        }
    
        self.transactions = []  # Vaciar transacciones pendientes
        self.chain.append(block)
        self.save_blockchain()
        self.sync_with_network()
        self.broadcast_new_block(block)

        print(f"✅ Bloque minado: {block}")
        return block

    def broadcast_new_block(self, block):
        """Envía el nuevo bloque a todos los nodos"""
        for node in self.nodes.copy():
            try:
                requests.post(f"http://{node}/receive_block", json={"block": block}, timeout=3)
            except requests.exceptions.RequestException:
                print(f"⚠️ No se pudo enviar el bloque a {node}")

    def add_transaction(self, sender, receiver, amount):
        """Añade una transacción a la lista de transacciones pendientes"""
        if sender == receiver:
            return False  

        transaction = {'sender': sender, 'receiver': receiver, 'amount': amount}
        self.transactions.append(transaction)
        print(f"📝 Nueva transacción agregada: {transaction}")
        return True
    '''
    def save_data(self):
        """Guarda la blockchain y los nodos en archivos JSON"""
        data = {
            "chain": self.chain,
            "current_supply": self.current_supply,
            "nodes": list(self.nodes)
        }
        with open(BLOCKCHAIN_FILE, "w") as file:
            json.dump(data, file, indent=4)

    def load_data(self):
        """Carga la blockchain y los nodos desde archivos JSON"""
        if os.path.exists(BLOCKCHAIN_FILE):
            with open(BLOCKCHAIN_FILE, "r") as file:
                data = json.load(file)
                self.chain = data.get("chain", [])
                self.current_supply = data.get("current_supply", 0)
                self.nodes = set(data.get("nodes", []))
        else:
            self.create_genesis_block()
    '''
    def get_balance(self, address):
        """Consulta el saldo de una dirección"""
        balance = 0
        for block in self.chain:
            for transaction in block["transactions"]:
                if transaction["receiver"] == address:
                    balance += transaction["amount"]
                elif transaction["sender"] == address:
                    balance -= transaction["amount"]
        return max(0, round(balance, 2))

    def proof_of_work(self, previous_proof):
        """Sistema de prueba de trabajo"""
        new_proof = 1
        check_proof = False
        while not check_proof:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == "0000":
                check_proof = True
            else:
                new_proof += 1
        return new_proof

    @property
    def last_block(self):
        """Retorna el último bloque, o crea el bloque génesis si la blockchain está vacía"""
        if not self.chain:
            self.create_genesis_block()
        return self.chain[-1]
    
    def save_blockchain(self):
        """Guarda la blockchain en un archivo JSON"""
        data = {
            "chain": self.chain,
            "current_supply": self.current_supply,  # Guardamos el current_supply
            "nodes": list(self.nodes)  # 🔹 Guardamos los nodos en el archivo JSON
        }
        with open(BLOCKCHAIN_FILE, "w") as file:
            json.dump(data, file, indent=4)

    def load_blockchain(self):
        """Carga la blockchain y los nodos desde el archivo JSON"""
        #global current_supply
        if os.path.exists(BLOCKCHAIN_FILE):
            try:
                with open(BLOCKCHAIN_FILE, "r") as file:
                    data = json.load(file)
                    self.chain = data.get("chain", [])
                    self.current_supply = data.get("current_supply", 0)
                    self.nodes = set(data.get("nodes", []))  # 🔹 Cargamos los nodos guardados
            except (json.JSONDecodeError, FileNotFoundError):
                print("⚠️ Blockchain corrupta o no encontrada. Creando nueva...")
                self.chain = []
                self.create_genesis_block()
        else:
            print("🔄 Creando una nueva blockchain...")
            self.chain = []
            self.create_genesis_block()
    
app = Flask(__name__)
port = int(sys.argv[1]) if len(sys.argv) > 1 else 5001
blockchain = Blockchain(port)

def get_block_reward():
    """Calcula la recompensa de minería según el halving"""
    halvings = len(blockchain.chain) // HALVING_BLOCKS  
    return max(INITIAL_REWARD // (2 ** halvings), 1)  


@app.route('/mine_rewards', methods=['POST'])
def mine_rewards():
    """Minar recompensas y agregar bloques con transacciones"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Datos no recibidos"}), 400

    player = data.get("player")
    if not player:
        return jsonify({"error": "Datos incompletos"}), 400

    # Verificar límite diario de minería
    today = datetime.today().date()
    if player in last_mine_time:
        if last_mine_time[player]["date"] == today and last_mine_time[player]["mined"] >= MAX_DAILY_MINING:
            return jsonify({"error": "⚠️ Has alcanzado tu límite diario de minería."}), 429

    reward = get_block_reward()
    if blockchain.current_supply + reward > MAX_SUPPLY:
        return jsonify({"error": "No se pueden minar más GG Coin. Límite alcanzado."}), 400

    blockchain.add_transaction("sistema", player, reward)
    #proof = blockchain.proof_of_work(blockchain.last_block["proof"])
    proof = 1
    blockchain.create_block(proof=proof, previous_hash=hashlib.sha256(str(blockchain.last_block).encode()).hexdigest())

    blockchain.current_supply += reward  # Actualizar suministro total
    blockchain.update_supply_from_network() 
    #blockchain.save_blockchain()

     # Guardar registro de minería
    if player not in last_mine_time:
        last_mine_time[player] = {"date": today, "mined": 0}
    last_mine_time[player]["mined"] += reward

    return jsonify({"message": f"🎉 Has minado {reward} GG Coin!"}), 200





@app.route('/register_node', methods=['POST'])
def register_node():
    """Registrar un nodo en la red y evitar bucles infinitos"""
    data = request.get_json()
    node_address = data.get("node")

    if not node_address:
        return jsonify({"error": "No se proporcionó la dirección del nodo"}), 400

    # 🔹 Verificar si el nodo ya está registrado
    if node_address in blockchain.nodes:
        return jsonify({"message": "El nodo ya está registrado", "nodes": list(blockchain.nodes)}), 200

    blockchain.register_node(node_address)
    return jsonify({"message": "Nodo registrado correctamente", "nodes": list(blockchain.nodes)}), 200



@app.route('/get_balance', methods=['GET'])
def get_balance():
    """Consultar saldo de una dirección"""
    address = request.args.get("address")
    if not address:
        return jsonify({"error": "Dirección no proporcionada"}), 400

    balance = blockchain.get_balance(address)
    return jsonify({"balance": balance}), 200

@app.route('/send_transaction', methods=['POST'])
def send_transaction():
    """Verifica la firma y transfiere GG Coin de una wallet a otra"""
    data = request.get_json()
    sender = data.get("sender")
    receiver = data.get("receiver")
    amount = float(data.get("amount"))
    signature = data.get("signature")

    if not sender or not receiver or not amount or not signature:
        return jsonify({"error": "Datos incompletos"}), 400

    if amount <= 0:
        return jsonify({"error": "El monto a enviar debe ser mayor a 0"}), 400

    # **Calcular tarifas dinámicas**
    dynamic_fee = round(amount * DYNAMIC_FEE_RATE, 2)  # 0.5% del monto transferido
    total_fee = BASE_FEE + dynamic_fee
    #amount_after_fees = amount
    total_amount_deducted = amount + total_fee  # 🔹 El emisor paga el total con la comisión

    # **Sincronizar con la red antes de validar saldo**
    blockchain.sync_with_network()

    # **Verificar que la cantidad después de tarifas sea válida**
    sender_balance = blockchain.get_balance(sender)
    if sender_balance < total_amount_deducted:
        return jsonify({
            "error": "Fondos insuficientes",
            "required": total_amount_deducted,
            "available": sender_balance
        }), 400


    # **Buscar el user_id del remitente basado en su dirección**
    sender_user_id = blockchain.get_user_id_from_address(sender)
    if not sender_user_id:
        return jsonify({"error": "No se encontró el user_id del remitente"}), 400

    # **Cargar la wallet usando el user_id**
    sender_wallet = Wallet(sender_user_id)
    sender_public_key = sender_wallet.get_public_key()

    if not sender_public_key:
        return jsonify({"error": "No se encontró la clave pública del remitente"}), 400

    try:
        public_key = serialization.load_pem_public_key(sender_public_key.encode())
    except Exception:
        return jsonify({"error": "Clave pública inválida"}), 400

    # **Verificar la firma**
    message = f"{sender}->{receiver}:{amount}"
    try:
        public_key.verify(
            bytes.fromhex(signature),
            message.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    except Exception:
        return jsonify({"error": "Firma no válida"}), 400

    # **Evitar transacciones duplicadas**
    for tx in blockchain.transactions:
        if (tx["sender"] == sender and 
            tx["receiver"] == receiver and 
            tx["amount"] == amount and 
            abs(tx["timestamp"] - timestamp) < 2):  # Si la transacción es muy reciente, es duplicada
            return jsonify({"error": "Transacción duplicada detectada. Espera antes de volver a intentarlo."}), 400

    # **Agregar transacciones**
    blockchain.add_transaction(sender, receiver, amount)

    # 🔹 **Registrar la transacción de la tarifa (al fondo de minería)**
    blockchain.add_transaction(sender, "mining_fund", total_fee) 
    
    proof = blockchain.proof_of_work(blockchain.last_block["proof"])
    blockchain.create_block(proof=proof, previous_hash=hashlib.sha256(str(blockchain.last_block).encode()).hexdigest())
    
    return jsonify({
        "message": f"✅ Transacción enviada: {amount} GG a {receiver}.",
        "fee_paid": total_fee,
        "total_deducted_from_sender": total_amount_deducted,
        "net_received_by_receiver": amount
    }), 201



@app.route('/get_chain', methods=['GET'])
def get_chain():
    """Obtener toda la blockchain"""
    blockchain.sync_with_network()
    return jsonify({
        "chain": blockchain.chain, 
        "length": len(blockchain.chain),
        "current_supply": blockchain.current_supply  # 🔄 Agregar el supply en la respuesta
    }), 200

@app.route('/get_transactions', methods=['GET'])
def get_transactions():
    """Devuelve todas las transacciones almacenadas en la blockchain."""
    transactions = []
    for block in blockchain.chain:
        transactions.extend(block["transactions"])  # Agrega transacciones de cada bloque
    return jsonify({"transactions": transactions}), 200

@app.route('/receive_block', methods=['POST'])
def receive_block():
    """Recibe un nuevo bloque minado desde otro nodo"""
    data = request.get_json()
    if "block" not in data:
        return jsonify({"error": "Bloque no recibido"}), 400

    #block = data["block"]
    block = data.get("block")
    blockchain.chain.append(block)
    blockchain.save_blockchain()
    blockchain.update_supply_from_network() 
    return jsonify({"message": "Bloque recibido correctamente"}), 200

@app.route('/stats', methods=['GET'])
def blockchain_stats():
    """Devuelve estadísticas de la blockchain."""
    #blockchain.sync_with_network()  # Asegurar que el supply se actualiza antes de mostrarlo
    total_transactions = sum(len(block["transactions"]) for block in blockchain.chain)
    return jsonify({
        "total_blocks": len(blockchain.chain),
        "total_transactions": total_transactions,
        "current_supply": blockchain.current_supply
    }), 200

@app.route('/distribute_fees', methods=['POST'])
def distribute_fees():
    """Reparte las tarifas de transacción entre los nodos conectados."""
    if not blockchain.nodes:
        return jsonify({"error": "No hay nodos conectados."}), 400

    total_fees = sum(tx["amount"] for tx in blockchain.transactions if tx["receiver"] == "mining_fund")
    num_nodes = len(blockchain.nodes)
    reward_per_node = total_fees / num_nodes if num_nodes > 0 else 0

    for node in blockchain.nodes:
        blockchain.add_transaction("mining_fund", node, reward_per_node)

    return jsonify({"message": f"Tarifas de transacción distribuidas entre {num_nodes} nodos."}), 200

@app.route('/sync', methods=['GET'])
def sync():
    """Sincroniza la blockchain con otros nodos"""
    blockchain.sync_with_network()
    return jsonify({"message": "Blockchain sincronizada", "chain_length": len(blockchain.chain)}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=port, debug=True)
