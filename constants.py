from naeural_core.constants import ADMIN_PIPELINE, ADMIN_PIPELINE_FILTER


ADMIN_PIPELINE_FILTER = [
  *ADMIN_PIPELINE_FILTER,
  "ORACLE_SYNC_01",
]


ADMIN_PIPELINE = {
  **ADMIN_PIPELINE,
  
  'ORACLE_SYNC_01': {
  },
  
  "DEEPLOY_MANAGER": {
    "NGROK_EDGE_LABEL": "$EE_NGROK_EDGE_LABEL_DEEPLOY_MANAGER",
  },

  'ORACLE_API': {
    "NGROK_EDGE_LABEL": "$EE_NGROK_EDGE_LABEL_EPOCH_MANAGER",
    "PROCESS_DELAY": 0,
  },

  "NAEURAL_RELEASE_APP": {
    "NGROK_EDGE_LABEL": "$EE_NGROK_EDGE_LABEL_RELEASE_APP",
    "PROCESS_DELAY": 0,
  },
  
  "DAUTH_MANAGER" : {
    "NGROK_EDGE_LABEL": "$EE_NGROK_EDGE_LABEL_DAUTH_MANAGER",
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
      "EE_SWARM_KEY_CONTENT_BASE64"
    ],
    
    "AUTH_PREDEFINED_KEYS" : {
      # "EE_SUPERVISOR" : False, # this should not be enabled 
      "EE_SECURED" : 1
    },
  },
  
  'CSTORE_MANAGER': {
    "NGROK_EDGE_LABEL": "$EE_NGROK_EDGE_LABEL_CSTORE_MANAGER",
    "PROCESS_DELAY": 0,
  },
  
}


if __name__ == '__main__':
  print("")
