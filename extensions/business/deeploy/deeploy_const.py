"""
Examples:

- plugin_signature: "A_SIMPLE_PLUGIN"
- pipeline_input_type: "ExampleDatastream"




"""
from time import time
from uuid import uuid4

class DEEPLOY_ERRORS:
  GENERIC = "ERR01_DEEPLOY_GENERIC_ERROR"
  NODES1 = "ERR02_DEEPLOY_NODES1"
  NODES2 = "ERR03_DEEPLOY_NODES2"
  NODES3 = "ERR04_DEEPLOY_NODES3"
  NODES4 = "ERR05_DEEPLOY_NODES4"
  NODERES1 = "ERR06_DEEPLOY_TARGET_NODE_RESOURCES1"
  

DEEPLOY_CREATE_REQUEST = {
  "app_alias" : "some_app_name", 
  "plugin_signature" : "SOME_PLUGIN_01",
  "nonce" : hex(int(time() * 1000)), # recoverable via int(nonce, 16)
  "target_nodes" : [
    "0xai_node_1",
    "0xai_node_2",
  ],
  "target_nodes_count" : 0,
  "app_params" : {
    "IMAGE" : "repo/image:tag",
    "CR" : "docker.io",
    "CR_USERNAME" : "user",
    "CR_PASSWORD" : "password",
    "CONTAINER_RESOURCES" : {
      "cpu" : 1,
      "memory" : "512m"
    },
    "PORT" : None,
    "NGROK_EDGE_LABEL" : None,
    "NGROK_USE_API": True,
    "ENV" : {
      "ENV1" : "value1",
      "ENV2" : "value2",
      "ENV3" : "value3",
      "ENV4" : "value4",
    },
    "DYNAMIC_ENV" : {
      "ENV5" : [
        {
          "type" : "static",
          "value" : "http://"
        },
        {
          "type" : "host_ip",
          "value" : None
        },
        {
          "type" : "static",
          "value" : ":5080/test_api_endpoint"
        }
      ],
      "ENV6" : [
        {
          "type" : "host_ip",
          "value" : "http://"
        }
      ],
    },
    "RESTART_POLICY" : "always",
    "IMAGE_PULL_POLICY" : "always",
    
    
    "OTHER_PARAM1" : "value1",
    "OTHER_PARAM2" : "value2",
    "OTHER_PARAM3" : "value3",
    "OTHER_PARAM4" : "value4",
    "OTHER_PARAM5" : "value5",
  },
  "pipeline_input_type"  : "void",
  "pipeline_input_uri" : None,
  "chainstore_response" : False,
}


DEEPLOY_GET_APPS_REQUEST = {
  "nonce" : hex(int(time() * 1000)), # recoverable via int(nonce, 16)
}

DEEPLOY_DELETE_REQUEST = {
  "app_id" : "target_app_name_id_returned_by_get_apps_or_create_pipeline",
  "target_nodes" : [
    "0xai_target_node_1",
    "0xai_target_node_2",
  ],
  "nonce" : hex(int(time() * 1000)), # recoverable via int(nonce, 16)
}  
