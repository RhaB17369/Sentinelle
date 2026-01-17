
import requests
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class EqivoProbe:
    """
    Module de Signalisation utilisant l'API Open Source Eqivo.
    S'interface avec FreeSWITCH pour l'envoi de signaux actifs.
    """
    
    def __init__(self, base_url: str, auth_id: str, auth_token: str):
        self.base_url = base_url.rstrip('/')
        self.auth = (auth_id, auth_token)

    def send_silent_ping(self, target_number: str, sender_number: str) -> Dict[str, Any]:
        """
        Envoie un message via Eqivo configuré pour être un Silent SMS (Type 0).
        Note: Nécessite une configuration spécifique du 'Message Route' dans FreeSWITCH.
        """
        url = f"{self.base_url}/v1/Account/{self.auth[0]}/Message/"
        
        payload = {
            'src': sender_number,
            'dst': target_number,
            'text': '', # Corps vide pour un Ping
            'type': 'sms'
        }
        
        try:
            response = requests.post(url, auth=self.auth, data=payload, timeout=10)
            if response.status_code in [200, 201, 202]:
                data = response.json()
                logger.info(f"Signal Eqivo envoyé: {data.get('message_uuid')}")
                return {
                    "status": "sent",
                    "uuid": data.get("message_uuid"),
                    "provider": "Eqivo/FreeSWITCH"
                }
            else:
                return {"error": f"Eqivo API Error: {response.status_code}", "detail": response.text}
        except Exception as e:
            logger.error(f"Échec de la connexion à Eqivo: {e}")
            return {"error": str(e)}
