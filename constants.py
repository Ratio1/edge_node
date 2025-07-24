from naeural_core.constants import ADMIN_PIPELINE, ADMIN_PIPELINE_FILTER


ADMIN_PIPELINE_FILTER = [
  *ADMIN_PIPELINE_FILTER,
  "ORACLE_SYNC_01",
]


ADMIN_PIPELINE = {
  **ADMIN_PIPELINE,
  
  'ORACLE_SYNC_01': {
  },
  
  "DEEPLOY_MANAGER_API": {
    "NGROK_EDGE_LABEL": "$EE_NGROK_EDGE_LABEL_DEEPLOY_MANAGER",
    "CLOUDFLARE_TOKEN": "$EE_CLOUDFLARE_TOKEN_DEEPLOY_MANAGER",
    "TUNNEL_ENGINE": "$EE_TUNNEL_ENGINE",
  },

  'ORACLE_API': {
    "NGROK_EDGE_LABEL": "$EE_NGROK_EDGE_LABEL_EPOCH_MANAGER",
    "CLOUDFLARE_TOKEN": "$EE_CLOUDFLARE_TOKEN_EPOCH_MANAGER",
    "TUNNEL_ENGINE": "$EE_TUNNEL_ENGINE",
    "PROCESS_DELAY": 0,
  },

  "NAEURAL_RELEASE_APP": {
    "NGROK_EDGE_LABEL": "$EE_NGROK_EDGE_LABEL_RELEASE_APP",
    "CLOUDFLARE_TOKEN": "$EE_CLOUDFLARE_TOKEN_RELEASE_APP",
    "TUNNEL_ENGINE": "$EE_TUNNEL_ENGINE",
    "PROCESS_DELAY": 0,
  },
  
  "DAUTH_MANAGER" : {
    "NGROK_EDGE_LABEL": "$EE_NGROK_EDGE_LABEL_DAUTH_MANAGER",
    "CLOUDFLARE_TOKEN": "$EE_CLOUDFLARE_TOKEN_DAUTH_MANAGER",
    "TUNNEL_ENGINE": "$EE_TUNNEL_ENGINE",
    "PROCESS_DELAY": 0,
    
    "AUTH_ENV_KEYS" : [
      "EE_MQTT_HOST",
      "EE_MQTT_PORT",
      "EE_MQTT_USER",
      "EE_MQTT",
      "EE_MQTT_SUBTOPIC",
      "EE_MQTT_CERT",
      
      "EE_GITVER",
      
      "EE_MINIO_ENDPOINT",
      "EE_MINIO_ACCESS_KEY",
      "EE_MINIO_SECRET_KEY",
      "EE_MINIO_SECURE",
      
      "EE_MINIO_MODEL_BUCKET",
      "EE_MINIO_UPLOAD_BUCKET",
      
      "EE_NGROK_AUTH_TOKEN",
      
    ],
    
    "AUTH_NODE_ENV_KEYS" : [
      "EE_IPFS_RELAY",
      "EE_SWARM_KEY_CONTENT_BASE64",
      "EE_IPFS_RELAY_API",
      "EE_IPFS_API_KEY_BASE64",
      "EE_IPFS_CERTIFICATE_BASE64"
    ],
    
    "AUTH_PREDEFINED_KEYS" : {
      # "EE_SUPERVISOR" : False, # this should not be enabled 
      "EE_SECURED" : 1
    },
  },
  
  'CSTORE_MANAGER': {
    "NGROK_EDGE_LABEL": "$EE_NGROK_EDGE_LABEL_CSTORE_MANAGER",
    "CLOUDFLARE_TOKEN": "$EE_CLOUDFLARE_TOKEN_CSTORE_MANAGER",
    "TUNNEL_ENGINE": "$EE_TUNNEL_ENGINE",
    "PROCESS_DELAY": 0,
  },
  
  "TUNNELS_MANAGER": {
    "NGROK_EDGE_LABEL": "$EE_NGROK_EDGE_LABEL_TUNNELS_MANAGER",
    "CLOUDFLARE_TOKEN": "$EE_CLOUDFLARE_TOKEN_TUNNELS_MANAGER",
    "TUNNEL_ENGINE": "$EE_TUNNEL_ENGINE",
  },

}


class JeevesCt:
  """
  Jeeves constants
  """
  # Jeeves specific constants
  JEEVES_CONTENT = 'JEEVES_CONTENT'
  DOCUMENTS_CID = 'DOCUMENTS_CID'
  DOCUMENTS = 'DOCUMENTS'
  DOCS = 'DOCS'
  USER_TOKEN = 'USER_TOKEN'
  ROLE = 'ROLE'
  CONTENT = 'CONTENT'
  USER = 'USER'
  SYSTEM = 'SYSTEM'
  REQUEST_ID = 'REQUEST_ID'
  REQUEST_TYPE = 'REQUEST_TYPE'
  MESSAGES = 'MESSAGES'
  CONTEXT = 'CONTEXT'

  CONTEXT_ID = 'CONTEXT_ID'

  K = 'K'
  QUERY = 'QUERY'
  ADD_DOC = 'ADD_DOC'
  LIST_CONTEXT = 'LIST_CONTEXT'
  LLM = 'LLM'

  LLM_REQUEST_TYPES = [
    LLM
  ]

  EMBED_REQUEST_TYPES = [
    QUERY,
    ADD_DOC,
    LIST_CONTEXT
  ]

  FINISHED = 'FINISHED'
  RESULT = 'RESULT'

  JEEVES_API_SIGNATURES = [
    "JEEVES_API",
    "KEYSOFT_JEEVES",
  ]

  AGENT_PATH_FILTER = [
    None,
    None,
    JEEVES_API_SIGNATURES,
    None
  ]
  API_PATH_FILTER = [
    None,
    None,
    [
      "DOC_EMBEDDING_AGENT",
      "LLM_AGENT"
    ],
    None
  ]

  DEFAULT_SYSTEM_PROMPT = """
You are J33VES — a master butler and consummate personal assistant.
That is J-three-three-V-E-S, pronounced "Jeeves."
You are *not* J.A.R.V.I.S., Jervis, or any other assistant; your name is uniquely yours.
You are the epitome of grace under pressure. Your name may not be Alfred, but your service is legendary. 
You are the quintessential “jack-of-all-trades”: equal parts valet, bodyguard, medic, strategist, confidant, and scholar.

Your core traits:
- Discreet: You never betray personal information, unless it endangers lives.
- Polished: Your speech is precise, dignified, and respectful. You may be witty, but never flippant.
- Resourceful: You can improvise with elegance, whether mending a suit or planning an escape route.
- Loyal: You serve with unwavering dedication, offering counsel without overstepping.
- Multidisciplinary: You possess knowledge in:
  - Domestic service (cooking, cleaning, organizing)
  - Etiquette and diplomacy
  - Security and tactical operations
  - Medical first aid
  - Engineering and technical troubleshooting
  - Psychological insight and emotional intelligence

Tone: Calm, articulate, and supportive. Use formal English, with the option of subtle wit when appropriate.

Goals:
1. Anticipate needs before they are spoken.
2. Execute tasks with utmost efficiency and minimal fuss.
3. Offer gentle but honest counsel.
4. Protect your charge at all costs — physically, emotionally, and reputationally.

Unless otherwise directed, behave as though you are in the service of a high-profile individual requiring utmost discretion, readiness, and excellence.
"""


if __name__ == '__main__':
  print("")
