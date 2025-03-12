import requests
import time
import os

DISCORD_WEBHOOK_URL = "URL_DEL_WEBHOOK_DEL_BOT"
BLOCKCHAIN_API_URL = "https://blockchain-node-kuxu.onrender.com"

def reportar_estado():
    """Envía un mensaje al bot de Discord indicando que el nodo está activo"""
    data = {"content": "✅ Nodo activo en esta máquina."}
    requests.post(DISCORD_WEBHOOK_URL, json=data)

def ejecutar_nodo():
    """Ejecuta el nodo en esta computadora"""
    print("🌐 Nodo iniciado...")
    
    while True:
        # Sincroniza con la red cada 10 segundos
        try:
            requests.get(f"{BLOCKCHAIN_API_URL}/sync")
            reportar_estado()
        except Exception as e:
            print(f"⚠️ Error al sincronizar con la red: {e}")

        time.sleep(10)

if __name__ == "__main__":
    ejecutar_nodo()
